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
from romulus.sources.models import Window
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
    repo.record_hunt_process("h1", pid=4242, start_marker=marker, host="node1", command="hunt start", pgid=4242)
    repo.request_hunt_stop("h1", "hunt", "web:alice", now=utcnow() - timedelta(seconds=120))
    return s, repo


def test_force_stop_never_signals_a_pid_given_to_another_process(tmp_path):
    s, repo = _running(tmp_path)
    sent = []
    done = controls.force_stop(s, repo, "h1", actor="web:lead", role="lead", host="node1",
                               identify=lambda pid: ("boot:999", "python -m romulus.cli hunt start"),
                               send=lambda *call: sent.append(call), sleep=lambda _s: None)
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

    def send(pid, sig, pgid=None):
        sent.append((pid, sig, pgid))
        alive["yes"] = False

    def identify(pid):
        return ("boot:100", "python -m romulus.cli hunt start") if alive["yes"] else None
    done = controls.force_stop(s, repo, "h1", actor="web:lead", role="lead", host="node1", identify=identify,
                               send=send, sleep=lambda _s: None)
    assert sent == [(4242, signal.SIGTERM, 4242)] and done["changed"] == {"hunt": "partial"}

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


def test_a_stop_during_the_triage_pass_means_no_assessment_call(tmp_path):
    s = Settings(home=tmp_path)
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
    stop = {"detail": None}
    passes = []

    def triage(_heartbeat, cited=None):
        passes.append(cited)
        stop["detail"] = "requested by web:alice"       # the analyst stops it while the pass runs
        return {"status": "partial", "reason": "budget:stopped"}

    finish = [ToolCall("of", "finish_session", {"summary": "The review of this lead is complete."}, "{}")]
    # orient, and the session for the hypothesis the controller opens on the finding: then no assessment call
    provider = ScriptedProvider([response(tool_calls=finish), response(tool_calls=finish)])
    result = run_agent_phase(s, repo, "h1", provider=provider, toolbox_factory=lambda _s: Toolbox(repo, "h1"),
                             clock=lambda: 0.0, triage=triage, stop=lambda: stop["detail"])
    assert passes == [None]                             # the pass ran; its cited-group extension did not
    assert not [r for r in provider.requests if r.schema_name == "ai-assessment@1"]
    assert STOPPED_REASON in result.reason
    assert repo.agent_assessments("h1")[-1]["source"] == "template"


def test_the_triage_budget_starts_no_call_after_a_stop():
    from romulus.agent.provider import AgentStopped
    from romulus.agent.triage import TriageBudget
    budget = TriageBudget.from_settings(Settings())
    budget.check(100, 100)
    budget.stop = lambda: "requested by web:alice"
    with pytest.raises(AgentStopped) as stopped:
        budget.check(100, 100)
    assert stopped.value.budget == "stopped"


def test_a_refused_resume_never_replaces_the_live_workers_record(tmp_path, monkeypatch):
    from romulus import cli
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    owner = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True}, owner_token=owner)
    repo.record_hunt_process("h1", pid=4242, start_marker="boot:100", host="node1", command="hunt start")
    monkeypatch.setattr(cli, "_settings", lambda _args: s)
    monkeypatch.setattr(hunt_run, "open_repo", lambda _s: repo)
    for name in ("ensure_site_unchanged", "install_for_hunt"):
        monkeypatch.setattr(hunt_run, name, lambda *_a, **_k: None)
    assert cli.main(["hunt", "resume", "h1"]) == cli.EXIT_FAIL       # the live worker holds the lease
    row = repo.hunt_process("h1")
    assert row["pid"] == 4242 and row["ended_at"] is None


def test_the_agent_never_runs_on_a_hunt_stopped_during_its_sweep(tmp_path):
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    owner = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": False, "stopped": {"stage": "sweep"}},
               owner_token=owner)
    repo.set_hunt_state("h1", "partial", owner_token=owner, stop_reason="stopped by analyst")
    with pytest.raises(RuntimeError, match="detection finishes"):
        repo.claim_agent_lease("h1", 600)                # `agent reassess` claims this way
    with pytest.raises(RuntimeError, match="detection finishes"):
        repo.claim_triage_lease("h1", 600)               # `romulus triage` too
    assert repo.agent_reassessment_refusal("h1").startswith("The agent runs only after detection finishes")


# ------------------------------------------------------------------------------------------- the sweep run again
def _two_partition_source(monkeypatch):
    """Two partitions of Linux audit records: a downloader in the first, the interpreter it feeds in the second (the
    full pack's sequence, aggregate and baseline rules all read them)."""
    from tests.test_sweep import START, _complete

    def rec(rid, raw, ts):
        return {"_id": rid, "_index": "romulus-host-x", "_source": {
            "@timestamp": ts, "message": raw, "host": {"name": "video"},
            "event": {"dataset": "linux.audit", "original": raw}}}
    first = [rec("d1", 'type=EXECVE msg=audit(1731938698.000:7001): argc=2 a0="curl" a1="http://192.0.2.7/x"',
                 "2024-11-18T14:04:58Z"),
             rec("d2", 'type=SYSCALL msg=audit(1731938698.000:7001): syscall=59 success=yes ppid=500 pid=501 '
                       'comm="curl" exe="/usr/bin/curl"', "2024-11-18T14:04:58Z")]
    second = [rec("s1", 'type=EXECVE msg=audit(1731938701.000:7002): argc=1 a0="sh"', "2024-11-18T14:05:01Z"),
              rec("s2", 'type=SYSCALL msg=audit(1731938701.000:7002): syscall=59 success=yes ppid=500 pid=502 '
                        'comm="sh" exe="/usr/bin/dash"', "2024-11-18T14:05:01Z")]
    from romulus.hunt import sweep as sw
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: _complete(
        intent, first if intent.window.start == START else second))
    halves = [Window(start=START, end=START + timedelta(minutes=5)),
              Window(start=START + timedelta(minutes=5), end=START + timedelta(minutes=10))]
    return sw, halves


def _sweep_state(repo):
    candidates = sorted((c["id"], c["rule_id"], c["lane"], tuple(c["event_ids"]), c["claim"])
                        for c in repo.candidates("h1"))
    cells = sorted((c["rule_id"], c["target"], c["partition"], c["state"], c["matched"], c["evaluated"],
                    repr(c["detail"])) for c in repo.rule_cells("h1"))
    with repo.engine.connect() as connection:
        from romulus.store import schema as t
        tasks = sorted((row.id, row.state) for row in connection.execute(
            t.task.select().where(t.task.c.hunt_id == "h1")))
    return candidates, cells, tasks, list(repo.baseline_observations("h1"))


def test_a_sweep_stopped_part_way_and_run_again_stores_what_one_uninterrupted_sweep_stores(monkeypatch, tmp_path):
    from tests.test_sweep import FakeClient
    from tests.test_sweep import _repo as sweep_repo
    sw, halves = _two_partition_source(monkeypatch)
    window = Window(start=halves[0].start, end=halves[1].end)

    fresh = sweep_repo()
    sweep = sw.Sweep(fresh, FakeClient(), "h1", window, {"x": None}, stage_dir=tmp_path / "fresh")
    for half in halves:
        sweep.run_partition("romulus-host-x", None, [], half, est=2)
    sweep.finalize()
    expected = _sweep_state(fresh)
    assert any(row[1] == "host.downloader_feeds_interpreter" for row in expected[0])   # the aggregate published
    assert expected[3]                                                                  # baseline cells were stored

    stopped = sweep_repo()
    first = sw.Sweep(stopped, FakeClient(), "h1", window, {"x": None}, stage_dir=tmp_path / "first")
    requested = iter([None, "requested by web:alice"])
    first.stop_check = lambda: next(requested)
    first.run_partition("romulus-host-x", None, [], halves[0], est=2)
    with pytest.raises(HuntStopped):
        first.run_partition("romulus-host-x", None, [], halves[1], est=2)
    first.close_stage()
    assert not [c for c in stopped.candidates("h1") if c["rule_id"] == "host.downloader_feeds_interpreter"]

    again = sw.Sweep(stopped, FakeClient(), "h1", window, {"x": None}, stage_dir=tmp_path / "again")
    for half in halves:
        again.run_partition("romulus-host-x", None, [], half, est=2)
    again.finalize()
    assert _sweep_state(stopped) == expected


# ------------------------------------------------------------------------------------------- review follow-ups
ARKIME_FIELDS = {"firstPacket": "date", "lastPacket": "date", "network.community_id": "keyword"}


def _real_manifest_hunt(tmp_path, repo, s):
    """A hunt whose manifest is the real one: the pack, baseline specs and an Arkime session target besides a host
    target, with their profiles stored."""
    from romulus.hunt.manifest import build_manifest
    profiles = {
        "host-x": {"id": "p-host", "target": "host-x", "kind": "index", "backend_version": "t", "doc_count": 1,
                   "datasets": {}, "role": "host", "os_family": "linux", "field_types": {"@timestamp": "date"}},
        "arkime-x": {"id": "p-ark", "target": "arkime-x", "kind": "index", "backend_version": "t", "doc_count": 1,
                     "datasets": {}, "role": "network", "os_family": "unknown", "field_types": ARKIME_FIELDS},
    }
    manifest = build_manifest(s, Window(start=T, end=T + timedelta(hours=1)), {}, "broad", list(profiles), profiles)
    manifest["ai_agent"] = {"requested": False}
    repo.create_hunt("h1", manifest, "digest", "cli:web:alice")
    for profile in profiles.values():
        repo.save_profile("h1", profile)
    return manifest


def test_rules_of_stages_a_stop_skipped_read_partial_in_coverage_and_the_report(tmp_path, monkeypatch):
    from romulus.detect.packets import PACKET_PLAYBOOKS
    from romulus.report import markdown
    from romulus.report.manifest import build_manifest, coverage_for_hunt
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    manifest = _real_manifest_hunt(tmp_path, repo, s)
    owner = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True}, owner_token=owner)
    repo.request_hunt_stop("h1", "hunt", "web:alice")
    monkeypatch.setattr(hunt_run, "run_rank_pass", lambda *_a, **_k: None)
    watch = controls.StopWatch(repo, "h1", ("hunt",), ttl=0)
    _p, _b, expansion, stop = hunt_run._stages_after_sweep(s, repo, object(), "h1", None, {}, owner, watch)
    hunt_run._finish(repo, "h1", {"status": "disabled"}, {"finished": True, "complete": True},
                     expansion_summary=expansion, owner_token=owner, stopped=stop)

    rows = {row["rule_id"]: row for row in coverage_for_hunt(repo, "h1")["rules"]}
    owned = [item["id"] for item in manifest["baseline"]["specs"]] + [cls.id for cls in PACKET_PLAYBOOKS]
    for rule_id in owned:
        claim = rows[rule_id]["search_result"]
        # partial: "searched in part", or a positive-only rule's claim with its coverage incomplete
        assert claim.startswith("searched in part") or "coverage incomplete" in claim, (rule_id, claim)
        assert "no data in scope" not in claim and "searched in full" not in claim
    report = build_manifest(repo, "h1", "test")
    report["revision"] = {"number": 1, "id": "h1-r1", "supersedes": None}
    text = markdown.render(report)
    assert "no data in scope for this rule" not in "\n".join(
        line for line in text.splitlines() if any(rule_id in line for rule_id in owned))


def test_a_force_stop_after_the_sweep_marks_the_unfinished_stages_too(tmp_path):
    from romulus.report.manifest import coverage_for_hunt
    s = Settings(home=tmp_path, hunt_stop_grace_seconds=60)
    repo = _repo(tmp_path)
    manifest = _real_manifest_hunt(tmp_path, repo, s)
    owner = repo.claim_hunt("h1", 600)["lease_owner"]
    repo.audit("system", "hunt.sweep_summary", "h1", {"finished": True, "complete": True}, owner_token=owner)
    repo.record_hunt_process("h1", pid=4242, start_marker="boot:100", host="node1", command="hunt start")
    repo.request_hunt_stop("h1", "hunt", "web:alice", now=utcnow() - timedelta(seconds=120))
    controls.force_stop(s, repo, "h1", actor="web:lead", role="lead", host="node1", identify=lambda pid: None,
                        send=lambda *_a: pytest.fail("signalled"), sleep=lambda _s: None)
    rows = {row["rule_id"]: row for row in coverage_for_hunt(repo, "h1")["rules"]}
    for item in manifest["baseline"]["specs"]:
        claim = rows[item["id"]]["search_result"]
        assert claim.startswith("searched in part") or "coverage incomplete" in claim, (item["id"], claim)


def test_two_extensions_at_once_are_held_to_the_ceiling_together(tmp_path, monkeypatch):
    import threading
    s = Settings(home=tmp_path)                       # ceiling: 8 x 200 calls
    repo = _repo(tmp_path)
    _hunt(repo, s)
    both = threading.Barrier(2)
    resolve = hunt_budget.resolve

    def racing(*args, **kwargs):
        if kwargs.get("extensions") is None:          # the quick check outside the lock: both pass it together
            both.wait(timeout=10)
        return resolve(*args, **kwargs)
    monkeypatch.setattr(controls.hunt_budget, "resolve", racing)
    outcomes = []

    def extend():
        try:
            controls.extend_budget(s, repo, "h1", actor="web:alice", role="analyst", amounts={"max_calls": 900})
            outcomes.append("added")
        except ControlRefused as exc:
            outcomes.append(str(exc))
    threads = [threading.Thread(target=extend) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("added") == 1 and any("only a lead" in item for item in outcomes)
    monkeypatch.setattr(controls.hunt_budget, "resolve", resolve)
    limits = hunt_budget.resolve(repo, "h1", repo.get_hunt("h1")["manifest"], s)["limits"]
    assert limits["max_calls"] == s.agent_max_calls + 900 <= hunt_budget.ceiling(s)["max_calls"]


def test_a_cost_of_zero_removes_the_sites_cost_budget_so_only_a_lead_may_choose_it(tmp_path):
    s = Settings(home=tmp_path, agent_max_cost_usd=5.0)
    with pytest.raises(hunt_budget.BudgetRefused, match="only a lead"):
        hunt_budget.choose(s, "standard", {"max_cost_usd": 0}, role="analyst", chosen_by="web:a")
    lead = hunt_budget.choose(s, "standard", {"max_cost_usd": 0}, role="lead", chosen_by="web:l")
    assert lead["limits"]["max_cost_usd"] == 0 and "max_cost_usd" in lead["above_ceiling"]
    # where the site sets no cost budget, 0 is the default and anyone may keep it or set one
    free = Settings(home=tmp_path)
    assert hunt_budget.choose(free, "standard", role="analyst", chosen_by="web:a")["limits"]["max_cost_usd"] == 0
    assert hunt_budget.choose(free, "standard", {"max_cost_usd": 3}, role="analyst", chosen_by="web:a")
    # an uncapped hunt is never given a cost budget by raising it to a profile, and cannot be extended by cost
    repo = _repo(tmp_path)
    repo.create_hunt("h1", {"window": WINDOW, "targets": [], "ai_agent": {
        "requested": True, "budgets": hunt_budget.pinned_block(lead)}}, "d", "cli:web:alice")
    done = controls.extend_budget(s, repo, "h1", actor="web:lead", role="lead", profile="deep")
    assert "max_cost_usd" not in done["extension"]["amounts"] and done["limits"]["max_cost_usd"] == 0
    with pytest.raises(ControlRefused, match="no cost budget"):
        controls.extend_budget(s, repo, "h1", actor="web:lead", role="lead", amounts={"max_cost_usd": 2})


def test_the_command_line_extends_any_hunt_within_the_ceiling_without_a_lead_login(tmp_path, monkeypatch, capsys):
    from romulus import cli
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s, created_by="cli:web:someone-else")
    monkeypatch.setattr(cli, "_settings", lambda _args: s)
    monkeypatch.setattr(hunt_run, "open_repo", lambda _s: repo)
    monkeypatch.setenv("USER", "operator")
    assert cli.main(["hunt", "extend", "h1", "--calls", "50", "--no-continue"]) == cli.EXIT_OK
    row = repo.agent_budget_extensions("h1")[-1]
    assert row["added_by"] == "cli:operator" and row["role"] == "analyst"
    too_much = str(hunt_budget.ceiling(s)["max_calls"])
    assert cli.main(["hunt", "extend", "h1", "--calls", too_much, "--no-continue"]) == cli.EXIT_FAIL
    assert "only a lead" in capsys.readouterr().err


def test_process_identity_reads_the_start_marker_and_command_line_from_proc(tmp_path):
    root = tmp_path / "proc"
    (root / "sys" / "kernel" / "random").mkdir(parents=True)
    (root / "sys" / "kernel" / "random" / "boot_id").write_text("boot-1\n", encoding="ascii")
    (root / "77").mkdir()
    # the command name may hold spaces and parentheses: fields are read after the last ")"
    fields = ["S", "1", "77", "77", "0", "-1", "4194560"] + [str(n) for n in range(10, 22)] + ["123456", "0"]
    (root / "77" / "stat").write_text("77 (python (x) y) " + " ".join(fields), encoding="ascii")
    (root / "77" / "cmdline").write_bytes(b"python\0-m\0romulus.cli\0hunt\0start\0")
    assert controls.process_identity(77, root=root) == ("boot-1:123456", "python -m romulus.cli hunt start")
    (root / "77" / "stat").write_text("77 (python) Z " + " ".join(fields[1:]), encoding="ascii")
    assert controls.process_identity(77, root=root) is None          # a zombie has ended
    assert controls.process_identity(78, root=root) is None          # gone


def test_force_stop_reports_a_process_it_may_not_signal(tmp_path):
    s, repo = _running(tmp_path)

    def denied(*_args):
        raise PermissionError("operation not permitted")
    with pytest.raises(ControlRefused, match="may not signal"):
        controls.force_stop(s, repo, "h1", actor="web:lead", role="lead", host="node1",
                            identify=lambda pid: ("boot:100", "python -m romulus.cli hunt start"),
                            send=denied, sleep=lambda _s: None)
    assert repo.get_hunt("h1")["execution_state"] == "running"


def test_force_stop_leaves_a_hunt_a_resume_took_over_as_it_is(tmp_path):
    _settings, repo = _running(tmp_path)
    with pytest.raises(ValueError, match="another worker"):
        repo.end_force_stopped("h1", request_id=repo.latest_stop("h1")["id"], actor="web:lead",
                               hunt_owner=repo.get_hunt("h1")["lease_owner"], agent_owner=None, pid=9999,
                               start_marker="boot:1")
    request = repo.latest_stop("h1")["id"]
    repo.clear_stops("h1", "cli:x")
    with pytest.raises(ValueError, match="cleared meanwhile"):
        repo.end_force_stopped("h1", request_id=request, actor="web:lead",
                               hunt_owner=repo.get_hunt("h1")["lease_owner"], agent_owner=None, pid=4242,
                               start_marker="boot:100")
    assert repo.get_hunt("h1")["execution_state"] == "running"


def test_a_resume_clears_only_the_stops_requested_before_it_claimed_the_hunt(tmp_path):
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    repo.claim_hunt("h1", 600)
    first = repo.request_hunt_stop("h1", "hunt", "web:alice")
    repo.honor_stop(first["id"], "sweep")
    later = repo.request_hunt_stop("h1", "agent", "web:alice")
    assert repo.clear_stops("h1", "cli:x", up_to_id=first["id"]) == 1
    assert repo.latest_stop("h1")["id"] == later["id"] and repo.latest_stop("h1")["state"] == "requested"


def test_an_open_stop_whose_worker_died_says_so_in_the_banner(tmp_path):
    from romulus.web.control_routes import stop_banner
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    repo.claim_hunt("h1", 600)
    repo.request_hunt_stop("h1", "hunt", "web:alice")
    assert "stops at its next safe point" in stop_banner(repo, "h1")["text"]
    with repo.engine.begin() as connection:
        from romulus.store import schema as t
        connection.execute(t.hunt.update().where(t.hunt.c.id == "h1").values(lease_until=utcnow() - timedelta(1)))
    assert "no longer running" in stop_banner(repo, "h1")["text"]


def test_a_hunt_stop_reaching_only_the_agent_keeps_complete_detection_complete(tmp_path):
    from romulus.web.control_routes import stop_banner
    stop = {"scope": "hunt", "state": "honored", "requested_by": "web:alice", "requested_at": "2026-11-17T10:00",
            "honored_in": ["agent"], "forced_by": None}
    text = stop_sentence({"execution_state": "completed_within_scope", "controls": {"stop": stop}})
    assert "detection results are complete within scope" in text and "These results are partial" not in text
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s)
    _completed(repo)
    repo.claim_agent_lease("h1", 600)
    row = repo.request_hunt_stop("h1", "hunt", "web:alice")
    repo.honor_stop(row["id"], "agent")
    assert "detection results are complete within scope" in stop_banner(repo, "h1")["text"]


def test_a_stop_through_the_real_run_and_sweep_names_the_unstarted_source_and_a_resume_finishes(
        tmp_path, monkeypatch):
    from romulus.hunt import sweep as sweep_module
    from romulus.sources.models import Completeness, SearchOutcome
    from tests.test_baseline_sweep import FakeClient, _contract, _exec
    s = Settings(home=tmp_path)
    repo = _repo(tmp_path)
    _hunt(repo, s, targets=("x", "y"), requested=False)
    _patched_run(monkeypatch, repo)
    contracts = {"x": _contract("x"), "y": _contract("y")}
    monkeypatch.setattr(hunt_run, "_contracts", lambda *_a, **_k: contracts)
    monkeypatch.setattr(hunt_run, "ElasticClient", lambda *_a, **_k: FakeClient())
    halves = [Window(start=T, end=T + timedelta(minutes=30)), Window(start=T + timedelta(minutes=30),
                                                                     end=T + timedelta(hours=1))]
    events = {half.start: [_exec(f"e-{index}", half.start + timedelta(minutes=1))]
              for index, half in enumerate(halves)}
    reads = []
    stop_after_first = {"on": True}

    def execute(_client, intent, _contract):
        reads.append((intent.target, intent.window.start))
        if stop_after_first["on"] and len(reads) == 1:
            repo.request_hunt_stop("h1", "hunt", "web:alice")       # the analyst stops it while x is read
        records = [{"_index": "fixture", "_id": e.id, "_source": {}} for e in events.get(intent.window.start, [])]
        now = utcnow()
        return SearchOutcome(target=intent.target, fingerprint="f", started_at=now, ended_at=now,
                             completeness=Completeness.complete, total=len(records), total_relation="eq",
                             returned=len(records), records=records)
    by_id = {e.id: e for batch in events.values() for e in batch}
    monkeypatch.setattr(sweep_module, "execute", execute)
    monkeypatch.setattr(sweep_module, "normalize_hits",
                        lambda fetched, _boots=None, **_kw: ([by_id[row["_id"]] for row in fetched], {}, []))
    monkeypatch.setattr(sweep_module, "plan_partitions", lambda *_a, **_k: [(half, 1) for half in halves])
    monkeypatch.setattr(sweep_module.Sweep, "_window_dataset_counts", lambda *_a, **_k: (None, "fixture"))
    owner = repo.claim_hunt("h1", 600)["lease_owner"]

    result = hunt_run.run_hunt(s, "h1", claimed_owner=owner)
    assert result["execution_state"] == "partial"
    assert [target for target, _ in reads] == ["x"]                    # nothing read after the stop
    summary = repo.latest_audit("h1", "hunt.sweep_summary")["detail"]
    assert summary["stopped"]["target"] == "x" and summary["stopped"]["not_started"] == ["y"]
    assert any(c["target"] == "x" and c["partition"] == halves[1].key() and c["state"] == "planned"
               for c in repo.rule_cells("h1"))
    assert repo.latest_stop("h1")["state"] == "honored"

    stop_after_first["on"] = False
    reads.clear()
    monkeypatch.setattr(hunt_run, "_site_network_check", lambda *_a, **_k: {"warning": None})
    monkeypatch.setattr(hunt_run, "_stages_after_sweep", lambda *_a, **_k: ({}, {}, {}, None))
    monkeypatch.setattr(hunt_run, "run_hunt_segment_writer", lambda *_a, **_k: {})
    monkeypatch.setattr(hunt_run, "_ai_agent_phase", lambda *_a, **_k: {"status": "skipped"})
    resumed = hunt_run.resume_hunt(s, "h1", actor="cli:web:alice")
    assert sorted({target for target, _ in reads}) == ["x", "y"]
    assert repo.latest_audit("h1", "hunt.sweep_summary")["detail"]["finished"] is True
    assert resumed["execution_state"] in ("completed_within_scope", "partial")
    # every partition the stop left planned was read (baseline exec pairs wait for the baseline stage, not run here)
    assert not [c for c in repo.rule_cells("h1") if c["state"] == "planned" and not c["rule_id"].startswith("bl.")]
