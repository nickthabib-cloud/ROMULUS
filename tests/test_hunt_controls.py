"""Analyst controls over a hunt: per-hunt agent budgets (profiles, the site ceiling by role, pinning, extensions),
stopping a hunt or its agent at safe points, force stop, and how a stopped hunt reads in the report."""
import signal
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest

from romulus.agent import hunt_budget
from romulus.agent.investigate import STOPPED_REASON, _budget, run_agent_phase
from romulus.agent.provider.base import ToolCall
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.hunt import controls
from romulus.hunt import run as hunt_run
from romulus.hunt.controls import ControlRefused, HuntStopped
from romulus.report.markdown import outcome_sentence, stop_sentence
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo
from tests.agent_scripted import ScriptedProvider, response

T = datetime(2024, 11, 18, 10, tzinfo=UTC)
WINDOW = {"start": T.isoformat(), "end": (T + timedelta(hours=1)).isoformat()}


def _repo(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite")
    migrate(engine)
    return Repo(engine)


def _manifest(settings, *, profile="standard", requested=True, targets=("a", "b"), **overrides):
    choice = hunt_budget.choose(settings, profile, overrides, role="analyst", chosen_by="web:alice")
    return {"window": WINDOW, "targets": list(targets),
            "ai_agent": {"requested": requested,
                         "budgets": {"max_calls": 1, "max_tokens": 1000, "max_wall_seconds": 60,
                                     **hunt_budget.pinned_block(choice)}}}


def _hunt(repo, settings, hunt_id="h1", created_by="cli:web:alice", **kwargs):
    repo.create_hunt(hunt_id, _manifest(settings, **kwargs), "digest", created_by)


def _completed(repo, hunt_id="h1"):
    owner = repo.claim_hunt(hunt_id, 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", hunt_id, {"finished": True, "complete": True}, owner_token=owner)
    repo.set_hunt_state(hunt_id, "completed_within_scope", owner_token=owner, detection_result="leads_only",
                        stop_reason="frontier complete")


# ------------------------------------------------------------------------------------------- profiles and ceiling
def test_profiles_scale_the_standard_limits_and_deep_stays_within_the_default_ceiling():
    s = Settings()
    quick, standard, deep = (hunt_budget.profile_limits(s, name) for name in hunt_budget.PROFILES)
    assert standard == hunt_budget.standard_limits(s)
    assert standard["max_calls"] == s.agent_max_calls and standard["max_source_queries"] == s.agent_max_source_queries
    for key in ("max_calls", "max_tokens", "max_wall_seconds", "max_source_queries", "max_hypotheses"):
        assert quick[key] < standard[key] < deep[key]
    assert deep["max_wall_seconds"] == 6 * s.agent_max_wall_seconds        # hours for a mission hunt
    ceiling = hunt_budget.ceiling(s)
    assert all(deep[key] <= ceiling[key] for key in hunt_budget.LIMITS if key != "max_cost_usd")
    # every limit stays within its setting's own maximum
    assert ceiling["max_sessions_per_hypothesis"] == 20 and ceiling["max_initial_hypotheses"] == 40


def test_the_ceiling_binds_analysts_and_a_lead_goes_above_it_only_up_to_the_hard_maximum():
    s = Settings(agent_budget_ceiling_multiplier=2.0)
    above = {"max_calls": s.agent_max_calls * 3}
    with pytest.raises(hunt_budget.BudgetRefused, match="only a lead"):
        hunt_budget.choose(s, "standard", above, role="analyst", chosen_by="web:a")
    with pytest.raises(hunt_budget.BudgetRefused, match="only a lead"):
        hunt_budget.choose(s, "deep", role="analyst", chosen_by="web:a")     # deep is 4x: above a 2x ceiling
    lead = hunt_budget.choose(s, "standard", above, role="lead", chosen_by="web:l")
    assert lead["limits"]["max_calls"] == s.agent_max_calls * 3 and lead["above_ceiling"] == ["max_calls"]
    with pytest.raises(hunt_budget.BudgetRefused, match="maximum"):
        hunt_budget.choose(s, "standard", {"max_calls": 100_001}, role="lead", chosen_by="web:l")
    with pytest.raises(hunt_budget.BudgetRefused, match="at least"):
        hunt_budget.choose(s, "standard", {"max_wall_seconds": 10}, role="lead", chosen_by="web:l")


# --------------------------------------------------------------------------------------------- pinned budgets
def test_the_pinned_budget_survives_a_config_change_and_every_resume_reads_it(tmp_path):
    created = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, created, profile="deep")
    later = Settings(home=tmp_path, agent_max_calls=7, agent_max_source_queries=3, agent_max_hypotheses=2)
    pinned = hunt_budget.hunt_settings(later, repo, "h1")
    deep = hunt_budget.profile_limits(created, "deep")
    assert pinned.agent_max_calls == deep["max_calls"] and pinned.agent_max_source_queries == deep["max_source_queries"]
    assert pinned.agent_max_hypotheses == deep["max_hypotheses"]
    # the agent's own budget gate reads the pinned limits, not the live ones
    budget = _budget(later, repo.get_hunt("h1")["manifest"], repo, "h1", lambda: 0.0)
    assert budget.limits.max_calls == deep["max_calls"]
    # resolving the already-resolved settings again adds nothing twice
    assert hunt_budget.hunt_settings(pinned, repo, "h1") is pinned
    assert hunt_budget.resolve(repo, "h1", repo.get_hunt("h1")["manifest"], pinned)["limits"] == deep


def test_a_hunt_created_before_pinning_reads_unrecorded_limits_from_the_settings_and_says_so(tmp_path):
    repo = _repo(tmp_path)
    repo.create_hunt("old", {"window": WINDOW, "targets": [], "ai_agent": {
        "requested": True, "budgets": {"max_calls": 9, "max_tokens": 5000, "max_wall_seconds": 600}}}, "d", "t")
    resolved = hunt_budget.resolve(repo, "old", repo.get_hunt("old")["manifest"], Settings(agent_max_hypotheses=3))
    assert resolved["source"] == "settings" and resolved["limits"]["max_calls"] == 9
    assert resolved["limits"]["max_hypotheses"] == 3 and "max_hypotheses" in resolved["from_settings"]
    assert "max_calls" not in resolved["from_settings"]


def test_the_agent_phase_runs_on_the_pinned_budget_plus_extensions(tmp_path, monkeypatch):
    created = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, created)
    _completed(repo)
    repo.add_budget_extension("h1", added_by="web:alice", role="analyst", amounts={"max_calls": 5},
                              profile=None, above_ceiling=[], max_extensions=100)
    seen = {}

    def phase(settings, *_args, **kwargs):
        seen["settings"] = settings
        seen["stop"] = kwargs.get("stop")
        return type("R", (), {"as_dict": lambda self: {"status": "completed", "reason": None}})()

    monkeypatch.setattr(hunt_run, "run_agent_phase", phase)
    monkeypatch.setattr(hunt_run, "agent_readiness", lambda *_a: type("R", (), {"ready": True})())
    monkeypatch.setattr(hunt_run, "build_provider", lambda *_a, **_k: object())
    live = Settings(home=tmp_path, agent_max_calls=3, agent_triage="off")
    hunt_run._ai_agent_phase(live, repo, "h1", repo.get_hunt("h1")["manifest"], None, object(), {})
    assert seen["settings"].agent_max_calls == created.agent_max_calls + 5
    assert seen["stop"] is not None


# ------------------------------------------------------------------------------------------------- extensions
def test_an_extension_adds_to_the_pinned_limits_within_the_ceiling_and_is_audited(tmp_path):
    s = Settings(home=tmp_path, agent_budget_ceiling_multiplier=2.0)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    done = controls.extend_budget(s, repo, "h1", actor="web:alice", role="analyst",
                                  amounts={"max_calls": 50, "max_wall_seconds": 600})
    assert done["limits"]["max_calls"] == s.agent_max_calls + 50
    resolved = hunt_budget.resolve(repo, "h1", repo.get_hunt("h1")["manifest"], s)
    assert resolved["added"]["max_calls"] == 50 and resolved["limits"]["max_wall_seconds"] == s.agent_max_wall_seconds + 600
    audit = repo.latest_audit("h1", "hunt.agent_budget_extended")
    assert audit["actor"] == "web:alice" and audit["detail"]["amounts"] == {"max_calls": 50, "max_wall_seconds": 600}
    # the new total, not the amount, is held to the ceiling
    with pytest.raises(ControlRefused, match="only a lead"):
        controls.extend_budget(s, repo, "h1", actor="web:alice", role="analyst", amounts={"max_calls": 200})
    controls.extend_budget(s, repo, "h1", actor="web:lead", role="lead", amounts={"max_calls": 200})
    # another analyst may not extend alice's hunt; a profile raises every limit to its values
    with pytest.raises(ControlRefused, match="started this hunt"):
        controls.extend_budget(s, repo, "h1", actor="web:bob", role="analyst", profile="deep")
    with pytest.raises(ControlRefused, match="amounts to add or a budget profile"):
        controls.extend_budget(s, repo, "h1", actor="web:alice", role="analyst")


def test_extend_continues_a_budget_limited_agent_without_running_the_sweep_again(tmp_path, monkeypatch):
    s = Settings(home=tmp_path, agent_model="scripted-model")
    repo = _repo(tmp_path)
    monkeypatch.setattr(hunt_run, "open_repo", lambda _s: repo)
    _hunt(repo, s)
    _completed(repo)
    repo.save_agent_run({"hunt_id": "h1", "state": "partial", "reason": "budget:calls; cap:source_queries:hunt",
                         "prompt_digests": {}, "provider": {}, "started_at": utcnow() - timedelta(hours=1),
                         "ended_at": utcnow() - timedelta(minutes=5), "updated_at": utcnow()})
    for name in ("ensure_site_unchanged", "install_for_hunt"):
        monkeypatch.setattr(hunt_run, name, lambda *_a, **_k: None)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda *_a, **_k: object())
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_a, **_k: {})
    for name in ("Sweep", "_packet_stage", "_baseline_stage", "_run_expansion_safely", "run_rank_pass"):
        monkeypatch.setattr(hunt_run, name, lambda *_a, **_k: pytest.fail("a deterministic stage ran"))
    ran = []
    monkeypatch.setattr(hunt_run, "_ai_agent_phase", lambda *a, **k: ran.append(k) or {"status": "completed"})

    # a budget-limited run is not continued until budget is added after it ended
    with pytest.raises(ValueError, match="no agent run to continue"):
        hunt_run.resume_hunt(s, "h1", continue_agent=True)
    controls.extend_budget(s, repo, "h1", actor="cli:web:alice", role="analyst", amounts={"max_calls": 20})
    result = hunt_run.resume_hunt(s, "h1", continue_agent=True, actor="cli:web:alice")
    assert ran == [{"resuming": True}] and result["execution_state"] == "completed_within_scope"


# ------------------------------------------------------------------------------------------------ agent stop
def test_a_stop_request_ends_the_agent_between_model_calls_and_keeps_what_it_stored(tmp_path):
    repo = _repo(tmp_path)
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {"requested": True}}, "d", "test")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "a deterministic process execution finding", "claim_type": "observed_action",
        "event_ids": [], "context_event_ids": [], "predicate_fields": [],
        "entities": [["host", "workstation-1", "host"]], "ts": datetime.now(UTC),
        "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "c1", "source_case_id": None, "source_anchor_id": None, "source_link_id": None})
    opens = [ToolCall("o1", "open_hypothesis", {"statement": "Review the first incident hypothesis"}, "{}"),
             ToolCall("of", "finish_session", {"summary": "The initial review is complete."}, "{}")]
    provider = ScriptedProvider([response(tool_calls=opens)])           # nothing more may be asked
    stop = {"detail": None}

    def watch():
        return stop["detail"]

    def after_orient(_session):
        return Toolbox(repo, "h1")

    original_chat = provider.chat

    def chat(request):
        result = original_chat(request)
        stop["detail"] = "requested by web:alice at 2026-11-17T10:00:00+00:00"   # the analyst stops it now
        return result
    provider.chat = chat

    result = run_agent_phase(Settings(home=tmp_path), repo, "h1", provider=provider, toolbox_factory=after_orient,
                             clock=lambda: 0.0, stop=watch)
    assert result.state == "partial" and STOPPED_REASON in result.reason
    assert len(provider.requests) == 1                                  # no investigation, no assessment call
    assert len(repo.agent_hypotheses("h1")) == 1                        # what it stored is kept
    assert repo.agent_run("h1")["state"] == "partial"
    assert repo.agent_assessments("h1")[-1]["source"] == "template"


def test_an_agent_stopped_before_it_starts_is_partial_and_resumable(tmp_path, monkeypatch):
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    _completed(repo)
    owner = repo.claim_agent_lease("h1", 600)["lease_owner"]
    repo.request_hunt_stop("h1", "agent", "web:alice")
    monkeypatch.setattr(hunt_run, "run_agent_phase", lambda *_a, **_k: pytest.fail("the agent ran"))
    summary = hunt_run._ai_agent_phase(s, repo, "h1", repo.get_hunt("h1")["manifest"], owner, object(), {})
    assert summary["status"] == "partial" and summary["reason"].startswith(STOPPED_REASON)
    assert repo.latest_stop("h1")["state"] == "honored"
    assert repo.latest_audit("h1", "hunt.stop_honored")["actor"] == "web:alice"


# ------------------------------------------------------------------------------------------------- hunt stop
class _StoppingSweep:
    """A sweep that publishes one finding from its first source, then meets the analyst's stop at its next partition."""
    instances: ClassVar[list] = []

    def __init__(self, repo, client, hunt_id, window, contracts, on_candidate=None, **_kwargs):
        self.repo, self.hunt_id = repo, hunt_id
        self.partial_reasons, self.stats, self.stop_check = [], {"partitions": 1}, None
        self.closed = self.finalized = False
        _StoppingSweep.instances.append(self)

    def run_target(self, target):
        self.repo.save_candidate({
            "id": f"c-{target}", "hunt_id": self.hunt_id, "rule_id": "host.test", "rule_version": "1",
            "claim": "found before the stop", "claim_type": "observed_action", "event_ids": [],
            "context_event_ids": [], "predicate_fields": [], "entities": [], "ts": None, "severity": "high",
            "confidence": "high", "lane": "high", "priority": 2.0, "priority_reasons": [], "gate_results": {},
            "benign_alternatives": [], "next_checks": [], "group_key": f"c-{target}", "source_case_id": None,
            "source_anchor_id": None, "source_link_id": None})
        self.repo.request_hunt_stop(self.hunt_id, "hunt", "web:alice")
        stopped = self.stop_check()
        if stopped:
            raise HuntStopped(stopped)

    def finalize(self):
        self.finalized = True

    def close_stage(self):
        self.closed = True


def _patched_run(monkeypatch, repo):
    monkeypatch.setattr(controls, "STOP_CHECK_SECONDS", 0.0)
    monkeypatch.setattr(hunt_run, "open_repo", lambda _s: repo)
    for name in ("ensure_site_unchanged", "install_for_hunt", "clear_stale_stages"):
        monkeypatch.setattr(hunt_run, name, lambda *_a, **_k: None)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda *_a, **_k: object())
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_a, **_k: {})


def test_stopping_a_hunt_mid_sweep_leaves_it_honestly_partial_and_resumable(tmp_path, monkeypatch):
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    _patched_run(monkeypatch, repo)
    monkeypatch.setattr(hunt_run, "Sweep", _StoppingSweep)
    owner = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.set_rule_cell("h1", "r.agg", "1", "*", "window", "no_match_complete", 0, 3, {}, owner_token=owner)
    result = hunt_run.run_hunt(s, "h1", claimed_owner=owner)

    hunt = repo.get_hunt("h1")
    sweep = _StoppingSweep.instances[-1]
    assert result["execution_state"] == hunt["execution_state"] == "partial"
    assert sweep.closed and not sweep.finalized                        # no aggregate over part of the window
    assert "stopped by analyst" in hunt["stop_reason"] and "sources not started: b" in hunt["stop_reason"]
    summary = repo.latest_audit("h1", "hunt.sweep_summary")["detail"]
    assert summary["finished"] is False and summary["stopped"]["not_started"] == ["b"]
    assert {c["state"] for c in repo.rule_cells("h1") if c["target"] == "*"} == {"evaluated_partial"}
    assert [c["id"] for c in repo.candidates("h1")] == ["c-a"]          # what it found is kept
    assert repo.latest_stop("h1")["state"] == "honored"
    assert repo.agent_run("h1") is None                                  # the agent never started

    # a resume runs the sweep again and clears the request
    class Finishing(_StoppingSweep):
        def run_target(self, target):
            assert self.stop_check() is None

    monkeypatch.setattr(hunt_run, "Sweep", Finishing)
    for name in ("_site_network_check",):
        monkeypatch.setattr(hunt_run, name, lambda *_a, **_k: {"warning": None})
    monkeypatch.setattr(hunt_run, "_stages_after_sweep", lambda *_a, **_k: ({}, {}, {}, None))
    monkeypatch.setattr(hunt_run, "run_hunt_segment_writer", lambda *_a, **_k: {})
    monkeypatch.setattr(hunt_run, "_ai_agent_phase", lambda *_a, **_k: {"status": "completed"})
    resumed = hunt_run.resume_hunt(s, "h1", actor="cli:web:alice")
    assert Finishing.instances[-1].finalized
    assert resumed["execution_state"] == "completed_within_scope"
    assert repo.latest_stop("h1")["state"] == "cleared"
    assert repo.latest_audit("h1", "hunt.stop_cleared")["actor"] == "cli:web:alice"


def test_a_stop_after_the_sweep_skips_the_later_stages_and_names_them(tmp_path, monkeypatch):
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    owner = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.request_hunt_stop("h1", "hunt", "web:alice")
    monkeypatch.setattr(hunt_run, "_packet_stage", lambda *_a, **_k: pytest.fail("the packet stage ran"))
    monkeypatch.setattr(hunt_run, "_baseline_stage", lambda *_a, **_k: pytest.fail("the baseline stage ran"))
    monkeypatch.setattr(hunt_run, "_run_expansion_safely", lambda *_a, **_k: pytest.fail("expansion ran"))
    monkeypatch.setattr(hunt_run, "run_rank_pass", lambda *_a, **_k: None)
    watch = controls.StopWatch(repo, "h1", ("hunt",), ttl=0)
    packet, baseline, _expansion, stop = hunt_run._stages_after_sweep(s, repo, object(), "h1", None, {}, owner, watch)
    assert stop["stage"] == "packet stage"
    assert stop["not_run"] == ["packet stage", "baseline stage", "expansion", "AI agent"]
    assert packet is None and baseline is None
    text = hunt_run.stopped_text(stop)
    assert "not run: packet stage, baseline stage, expansion, AI agent" in text and "partial" in text


# ------------------------------------------------------------------------------------------------- force stop
def _running(tmp_path, *, marker="boot:100"):
    s = Settings(home=tmp_path, hunt_stop_grace_seconds=60)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    repo.claim_hunt("h1", 600)
    repo.record_hunt_process("h1", pid=4242, start_marker=marker, host="node1", command="hunt start")
    repo.request_hunt_stop("h1", "hunt", "web:alice", now=utcnow() - timedelta(seconds=120))
    return s, repo


def test_force_stop_never_signals_a_pid_given_to_another_process(tmp_path):
    s, repo = _running(tmp_path)
    sent = []
    done = controls.force_stop(s, repo, "h1", actor="web:lead", role="lead", host="node1",
                               identify=lambda pid: ("boot:999", "python -m romulus.cli hunt start"),
                               send=lambda pid, sig: sent.append((pid, sig)), sleep=lambda _s: None)
    assert sent == [] and done["signalled"] is False
    # the recorded worker is gone, so the hunt is left resumable all the same
    hunt = repo.get_hunt("h1")
    assert hunt["execution_state"] == "partial" and hunt["stop_reason"].startswith("interrupted: force-stopped")
    assert repo.latest_audit("h1", "hunt.sweep_summary")["detail"]["stopped"]["force"] is True
    assert repo.latest_stop("h1")["state"] == "forced"
    assert repo.latest_audit("h1", "hunt.force_stopped")["actor"] == "web:lead"


def test_force_stop_signals_only_a_live_romulus_worker_with_the_recorded_marker(tmp_path):
    s, repo = _running(tmp_path)
    alive = {"yes": True}
    sent = []

    def send(pid, sig):
        sent.append((pid, sig))
        alive["yes"] = False

    def identify(pid):
        return ("boot:100", "python -m romulus.cli hunt start") if alive["yes"] else None
    done = controls.force_stop(s, repo, "h1", actor="web:lead", role="lead", host="node1", identify=identify,
                               send=send, sleep=lambda _s: None)
    assert sent == [(4242, signal.SIGTERM)] and done["changed"] == {"hunt": "partial"}

    s, repo = _running(tmp_path / "other")
    with pytest.raises(ControlRefused, match="not a ROMULUS process"):
        controls.force_stop(s, repo, "h1", actor="web:lead", role="lead", host="node1",
                            identify=lambda pid: ("boot:100", "/usr/bin/sshd"),
                            send=lambda *_a: pytest.fail("signalled"), sleep=lambda _s: None)


@pytest.mark.parametrize("case", ["analyst", "grace", "host", "unverifiable", "no request"])
def test_force_stop_is_refused_unless_a_lead_waited_the_grace_period_on_the_workers_host(tmp_path, case):
    s, repo = _running(tmp_path, marker="unverifiable:4242" if case == "unverifiable" else "boot:100")
    kwargs = {"actor": "web:lead", "role": "lead", "host": "node1", "sleep": lambda _s: None,
              "identify": lambda pid: ("boot:100", "romulus"), "send": lambda *_a: pytest.fail("signalled")}
    if case == "analyst":
        kwargs["role"] = "analyst"
    elif case == "grace":
        kwargs["now"] = utcnow() - timedelta(seconds=90)
    elif case == "host":
        kwargs["host"] = "node2"
    elif case == "no request":
        repo.clear_stops("h1", "cli:x")
    with pytest.raises(ControlRefused):
        controls.force_stop(s, repo, "h1", **kwargs)
    assert repo.get_hunt("h1")["execution_state"] == "running"


def test_a_stop_needs_a_running_hunt_and_the_owner_or_a_lead(tmp_path):
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    with pytest.raises(ControlRefused, match="not running"):
        controls.request_stop(repo, "h1", scope="hunt", actor="web:alice", role="analyst")
    repo.claim_hunt("h1", 600)
    with pytest.raises(ControlRefused, match="started this hunt"):
        controls.request_stop(repo, "h1", scope="hunt", actor="web:bob", role="analyst")
    first = controls.request_stop(repo, "h1", scope="hunt", actor="web:alice", role="analyst")
    again = controls.request_stop(repo, "h1", scope="agent", actor="web:lead", role="lead")
    assert again["id"] == first["id"] and again["existing"]          # a hunt stop already covers the agent
    assert repo.latest_audit("h1", "hunt.stop_requested")["actor"] == "web:alice"
    # a run that ends before reaching a safe point leaves the request unapplied, never pending
    assert repo.mark_stops_unapplied("h1") == 1 and repo.latest_stop("h1")["state"] == "unapplied"


def test_the_worker_records_itself_and_its_end(tmp_path):
    repo = _repo(tmp_path)
    repo.create_hunt("h1", {"window": WINDOW, "targets": []}, "d", "t")
    with controls.worker(repo, "h1", "hunt start"):
        row = repo.hunt_process("h1")
        assert row["pid"] > 0 and row["ended_at"] is None and row["start_marker"]
    assert repo.hunt_process("h1")["ended_at"] is not None


def test_deleting_a_hunt_removes_its_controls(tmp_path):
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    repo.claim_hunt("h1", 600)
    repo.request_hunt_stop("h1", "hunt", "web:alice")
    repo.record_hunt_process("h1", pid=1, start_marker="m", host="h", command="c")
    repo.add_budget_extension("h1", added_by="web:a", role="lead", amounts={"max_calls": 1}, profile=None,
                              above_ceiling=[], max_extensions=1)
    with pytest.raises(ValueError, match="most one hunt keeps"):
        repo.add_budget_extension("h1", added_by="web:a", role="lead", amounts={"max_calls": 1}, profile=None,
                                  above_ceiling=[], max_extensions=1)
    owner = repo.get_hunt("h1")["lease_owner"]
    repo.set_hunt_state("h1", "failed", owner_token=owner)
    counts = repo.delete_hunt("h1", actor="web:lead")
    assert counts["stop_requests"] == 1 and counts["budget_extensions"] == 1 and counts["hunt_processes"] == 1


# ---------------------------------------------------------------------------------------------------- report
def test_report_wording_for_stopped_hunts():
    base = {"findings": [], "execution_state": "partial", "coverage": {}}
    stop = {"scope": "hunt", "state": "honored", "requested_by": "web:alice", "requested_at": "2026-11-17T10:00",
            "honored_in": ["sweep"], "forced_by": None}
    text = outcome_sentence({**base, "controls": {"stop": stop}})
    assert "An analyst stopped this hunt (requested by web:alice at 2026-11-17T10:00; it stopped at: sweep)" in text
    assert "unknown, not absent" in text and "These results are partial" in text
    assert "deterministic results do not depend on it" in stop_sentence({"controls": {"stop": {**stop,
                                                                                               "scope": "agent"}}})
    assert "force-stopped its worker" in stop_sentence({"controls": {"stop": {**stop, "state": "forced",
                                                                                 "forced_by": "web:lead"}}})
    assert "had not taken effect" in stop_sentence({"controls": {"stop": {**stop, "state": "requested"}}})
    assert stop_sentence({"controls": {"stop": {**stop, "state": "cleared"}}}) == ""


def test_the_report_records_the_stop_and_budget_and_both_renderers_say_so(tmp_path, monkeypatch):
    import json
    from xml.etree import ElementTree
    from zipfile import ZipFile

    from romulus.report import executive, markdown
    from romulus.report.manifest import build_manifest
    from tests.test_report import _repo_with_finding
    repo, _ = _repo_with_finding()
    with repo.engine.begin() as connection:
        from romulus.store import schema as t
        manifest = dict(connection.execute(t.hunt.select().where(t.hunt.c.id == "h1")).mappings().one()["manifest"])
        manifest["ai_agent"] = {**(manifest.get("ai_agent") or {}), "requested": True,
                                "budgets": hunt_budget.pinned_block(hunt_budget.choose(
                                    Settings(), "quick", role="analyst", chosen_by="web:alice"))}
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(
            manifest=manifest, execution_state="running", lease_owner="x", lease_until=utcnow() + timedelta(hours=1)))
    row = repo.request_hunt_stop("h1", "hunt", "web:alice")
    repo.honor_stop(row["id"], "sweep")
    m = build_manifest(repo, "h1", "test")
    assert m["controls"]["stop"]["state"] == "honored" and m["controls"]["agent_budget"]["profile"] == "quick"
    json.dumps(m, default=str)
    m["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    text = markdown.render(m)
    assert "| Analyst stop | An analyst stopped this hunt" in text and "| AI agent budget | quick profile" in text
    path = tmp_path / "report.docx"
    executive.write(m, path, "technical.md")
    with ZipFile(path) as docx:
        words = " ".join(node.text or "" for node in ElementTree.fromstring(docx.read("word/document.xml")).iter()
                         if node.tag.endswith("}t"))
    assert "An analyst stopped this hunt" in words


# ----------------------------------------------------------------------------------------- creation and continuation
def test_a_new_hunt_pins_its_chosen_budget_and_audits_the_choice(tmp_path, monkeypatch):
    from tests.test_expansion_budget_scale import _Client, _Profile
    monkeypatch.setattr(hunt_run, "ElasticClient", _Client)
    monkeypatch.setattr(hunt_run, "build_profile", lambda client, target: (_Profile(target), None))
    s = Settings(home=tmp_path, agent_default="off", es_index_patterns="logs-host")
    choice = hunt_budget.choose(s, "quick", {"max_calls": 33}, role="lead", chosen_by="web:lead")
    hunt_id = hunt_run.create_hunt(s, T, T + timedelta(hours=1), "cli:web:lead", agent_budget=choice)
    repo = hunt_run.open_repo(s)
    budgets = repo.get_hunt(hunt_id)["manifest"]["ai_agent"]["budgets"]
    assert budgets["schema"] == hunt_budget.BUDGET_SCHEMA and budgets["profile"] == "quick"
    assert budgets["max_calls"] == 33
    assert budgets["max_hypotheses"] == hunt_budget.profile_limits(s, "quick")["max_hypotheses"]
    assert budgets["triage"]["triage_max_calls"] == s.agent_triage_max_calls
    audit = repo.latest_audit(hunt_id, "hunt.agent_budget_chosen")
    assert audit["actor"] == "web:lead" and audit["detail"]["overrides"] == {"max_calls": 33}
    # without a choice a hunt gets the standard budget
    plain = hunt_run.create_hunt(s, T, T + timedelta(hours=1), "test")
    assert repo.get_hunt(plain)["manifest"]["ai_agent"]["budgets"]["profile"] == "standard"


ASSESSMENT = {"overall": [{"text": "The persisted finding is available for review.", "cites": [],
                           "kind": "hypothesis"}],
              "key_steps": [], "narrative": [], "confidence": {"overall": "low", "reasons": []},
              "alternatives": [], "gaps": [], "next_checks": []}


def test_added_budget_lets_a_budget_limited_agent_continue_from_its_persisted_work(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _repo(tmp_path)
    choice = hunt_budget.choose(s, "standard", {"max_calls": 2}, role="analyst", chosen_by="web:alice")
    repo.create_hunt("h1", {"window": {}, "targets": [], "ai_agent": {
        "requested": True, "budgets": hunt_budget.pinned_block(choice)}}, "d", "cli:web:alice")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "a deterministic process execution finding", "claim_type": "observed_action",
        "event_ids": [], "context_event_ids": [], "predicate_fields": [],
        "entities": [["host", "workstation-1", "host"]], "ts": datetime.now(UTC),
        "severity": "high", "confidence": "high", "lane": "high", "priority": 2.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "c1", "source_case_id": None, "source_anchor_id": None, "source_link_id": None})
    opens = [ToolCall("o1", "open_hypothesis", {"statement": "Review the first incident hypothesis"}, "{}"),
             ToolCall("of", "finish_session", {"summary": "The initial review is complete."}, "{}")]
    finish = [ToolCall("f", "finish_session", {"summary": "The evidence review is complete."}, "{}")]

    first = ScriptedProvider([response(tool_calls=opens), response(parsed=ASSESSMENT)])
    result = run_agent_phase(s, repo, "h1", provider=first, toolbox_factory=lambda _s: Toolbox(repo, "h1"),
                             clock=lambda: 0.0)
    assert result.state == "partial" and "budget:calls" in result.reason
    assert repo.agent_hypotheses("h1")[0]["sessions_run"] == 1     # its session met the budget before any call

    controls.extend_budget(s, repo, "h1", actor="web:alice", role="analyst", amounts={"max_calls": 10})
    later = ScriptedProvider([response(tool_calls=finish), response(parsed=ASSESSMENT)])
    result = run_agent_phase(s, repo, "h1", provider=later, toolbox_factory=lambda _s: Toolbox(repo, "h1"),
                             clock=lambda: 0.0)
    assert len(later.requests) == 2              # the hypothesis got its next session, then the assessment
    assert "budget:calls" not in (result.reason or "")
    assert repo.agent_hypotheses("h1")[0]["sessions_run"] == 2
    assert repo.agent_usage("h1")["calls"] == 4  # spending persisted across both runs
