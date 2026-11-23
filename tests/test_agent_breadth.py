"""Orient breadth: every unexplained cluster of reportable findings gets a hypothesis, best first in report order, up
to the initial cap, whatever orient itself opened; "unexplained" is read from typed state (hypothesis cites of
findings, evidence and links), never from model text, and a cluster cap makes the view partial, never complete."""
from datetime import UTC, datetime

from romulus.agent import clusters as cluster_module
from romulus.agent import hunt_budget
from romulus.agent.admission import AgentAdmission
from romulus.agent.aliases import AliasBook
from romulus.agent.clusters import cited_findings, hunt_clusters, unexplained_clusters
from romulus.agent.investigate import _controller_open_hypotheses, run_agent_phase
from romulus.agent.provider.base import ToolCall
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo
from tests.agent_scripted import ScriptedProvider, response

BODY = {"overall": [{"text": "The persisted finding is available for review.", "cites": [], "kind": "hypothesis"}],
        "key_steps": [], "narrative": [], "confidence": {"overall": "low", "reasons": []},
        "alternatives": [], "gaps": [], "next_checks": []}
# id, lane, priority: five separate findings on five hosts, so five clusters, in report order c-h3, c-h2, c-h1, c-l2,
# c-l1 (lane, then priority)
FINDINGS = (("c-h1", "high", 1.0), ("c-h2", "high", 2.0), ("c-h3", "high", 3.0), ("c-l1", "lead", 1.0),
            ("c-l2", "lead", 2.0))
REPORT_ORDER = ["c-h3", "c-h2", "c-h1", "c-l2", "c-l1"]


def _candidate(repo, finding_id, lane, priority, *, event_ids=()):
    repo.save_candidate({
        "id": finding_id, "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": f"deterministic finding {finding_id}", "claim_type": "observed_action", "event_ids": list(event_ids),
        "context_event_ids": [], "predicate_fields": [], "entities": [["host", f"ws-{finding_id}", "host"]],
        "ts": datetime.now(UTC), "severity": lane, "confidence": "high", "lane": lane, "priority": priority,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": finding_id, "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })


def _hunt(tmp_path, s, findings=FINDINGS):
    engine = make_engine(tmp_path / "db.sqlite")
    migrate(engine)
    repo = Repo(engine)
    choice = hunt_budget.choose(s, "standard", {}, role="lead", chosen_by="web:alice")
    window = {"start": "2024-11-18T10:00:00+00:00", "end": "2024-11-18T11:00:00+00:00"}
    repo.create_hunt("h1", {"window": window, "targets": [], "ai_agent": {
        "requested": True, "budgets": hunt_budget.pinned_block(choice)}}, "d", "cli:web:alice")
    repo.set_hunt_state("h1", "running")
    repo.set_hunt_state("h1", "completed_within_scope", detection_result="leads_only", stop_reason="scope")
    for finding_id, lane, priority in findings:
        _candidate(repo, finding_id, lane, priority)
    return repo


def _finish():
    return [ToolCall("f", "finish_session", {"summary": "The review of this lead is complete."}, "{}")]


class _ByKind(ScriptedProvider):
    """The assessment's schema gets the body, an orient page `orient_calls`, every investigate turn a finish."""

    def __init__(self, orient_calls, **kwargs):
        super().__init__([], **kwargs)
        self.orient_calls = orient_calls

    def chat(self, request):
        with self.lock:
            self.requests.append(request)
        if request.response_schema is not None:
            return response(parsed=BODY)
        if "Dossier index page" in str(request.messages[1]["content"]):
            return response(tool_calls=self.orient_calls)
        return response(tool_calls=_finish())


def _run(s, repo, provider):
    return run_agent_phase(s, repo, "h1", provider=provider, toolbox_factory=lambda _s: Toolbox(repo, "h1"),
                           clock=lambda: 0.0)


def _supported(repo, hypothesis) -> set[str]:
    return {row["target_id"] for row in repo.agent_hypothesis_cites(hypothesis_id=hypothesis["id"])
            if row["role"] == "support" and row["target_kind"] == "finding"}


def _controller_rows(repo):
    return sorted((row for row in repo.agent_hypotheses("h1") if row["statement"].startswith("Investigate incident")),
                  key=lambda row: (row["created_at"], row["id"]))


def test_clusters_are_in_report_order_and_none_is_explained_before_any_hypothesis(tmp_path):
    repo = _hunt(tmp_path, Settings(home=tmp_path))
    view = hunt_clusters(repo, "h1")
    assert [cluster.top["id"] for cluster in view.clusters] == REPORT_ORDER
    assert view.partial is None and view.findings == view.clustered == 5
    assert [cluster.top["id"] for cluster in unexplained_clusters(repo, "h1", view)] == REPORT_ORDER


def test_orient_that_opened_two_never_leaves_the_other_clusters_unexamined(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _hunt(tmp_path, s)
    book = AliasBook(repo, "h1")
    h3, h2 = book.alias_for("F", "c-h3"), book.alias_for("F", "c-h2")
    opens = [ToolCall("o1", "open_hypothesis", {"statement": "The top host shows a staged intrusion",
                                                "supporting": [h3], "questions": ["What ran first?"]}, "{}"),
             ToolCall("o2", "open_hypothesis", {"statement": "The second host was reached from the first",
                                                "supporting": [h2], "questions": ["How was it reached?"]}, "{}"),
             ToolCall("of", "finish_session", {"summary": "Two hypotheses opened."}, "{}")]
    result = _run(s, repo, _ByKind(opens, context=1_000_000))

    assert result.state in {"completed", "partial"}
    hypotheses = repo.agent_hypotheses("h1")
    # orient's two, and one for each cluster no hypothesis cited: N unexplained clusters, N controller hypotheses
    assert len(hypotheses) == 5
    controller = _controller_rows(repo)
    assert [sorted(_supported(repo, row)) for row in controller] == [["c-h1"], ["c-l2"], ["c-l1"]]
    assert all(row["confidence"] == "low" for row in controller)
    # every hypothesis was investigated, and no cluster is left unexplained
    assert all(int(row["sessions_run"]) >= 1 for row in hypotheses)
    assert unexplained_clusters(repo, "h1") == []


def test_one_broad_hypothesis_explains_at_most_its_best_three_clusters(tmp_path):
    from romulus.agent.clusters import CLUSTERS_PER_HYPOTHESIS
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _hunt(tmp_path, s)
    book = AliasBook(repo, "h1")
    # the shape that turned the top-up off: one orient hypothesis citing every cluster
    every = [book.alias_for("F", finding_id) for finding_id, _lane, _priority in FINDINGS]
    opens = [ToolCall("o1", "open_hypothesis", {"statement": "Every reported finding is one intrusion",
                                                "supporting": every, "questions": ["How do they connect?"]}, "{}"),
             ToolCall("of", "finish_session", {"summary": "One broad hypothesis opened."}, "{}")]
    _run(s, repo, _ByKind(opens, context=1_000_000))

    assert CLUSTERS_PER_HYPOTHESIS == 3
    # it explains its best three clusters; the two below them get controller hypotheses of their own, and are worked
    controller = _controller_rows(repo)
    assert [next(iter(_supported(repo, row))) for row in controller] == ["c-l2", "c-l1"]
    assert all(int(row["sessions_run"]) >= 1 for row in controller)
    assert unexplained_clusters(repo, "h1") == []


def test_hypotheses_citing_nothing_never_hold_a_clusters_place(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off", agent_max_initial_hypotheses=3)
    repo = _hunt(tmp_path, s)
    # orient fills its cap with hypotheses that cite nothing (mention-led ones, say), each with a question left
    opens = [ToolCall(f"o{n}", "open_hypothesis", {"statement": f"Mention-led hypothesis number {n}",
                                                   "questions": ["Is the text part of an attack?"]}, "{}")
             for n in range(3)]
    opens.append(ToolCall("of", "finish_session", {"summary": "Three hypotheses opened."}, "{}"))
    _run(s, repo, _ByKind(opens, context=1_000_000))

    # every high cluster still got its hypothesis, best first, and was worked
    controller = _controller_rows(repo)
    assert [next(iter(_supported(repo, row))) for row in controller][:3] == ["c-h3", "c-h2", "c-h1"]
    assert all(int(row["sessions_run"]) >= 1 for row in controller)
    assert unexplained_clusters(repo, "h1") == []


def test_a_provider_failing_every_session_is_not_fed_new_cluster_hypotheses(tmp_path):
    from romulus.agent.investigate import FAILED_ROUNDS_LIMIT, SESSIONS_FAILED_REASON

    class _Failing(_ByKind):
        def chat(self, request):
            if request.response_schema is None and "Dossier index page" not in str(request.messages[1]["content"]):
                with self.lock:
                    self.requests.append(request)
                raise RuntimeError("the endpoint answered with an error")
            return super().chat(request)

    s = Settings(home=tmp_path, agent_triage="off", agent_max_initial_hypotheses=1)
    repo = _hunt(tmp_path, s)
    result = _run(s, repo, _Failing(_finish(), context=1_000_000))
    investigate = [row for row in repo.agent_sessions("h1") if row["purpose"] == "investigate"]
    assert all(row["state"] == "failed" for row in investigate)
    # two failed rounds of one session each, then the scheduling stops; not one session per cluster and retry
    assert len(investigate) == FAILED_ROUNDS_LIMIT
    assert SESSIONS_FAILED_REASON in (result.reason or "")


class _Outage(_ByKind):
    """Orient and the assessment answer; every investigate call fails (an endpoint error, not an outage)."""

    def chat(self, request):
        if request.response_schema is None and "Dossier index page" not in str(request.messages[1]["content"]):
            with self.lock:
                self.requests.append(request)
            raise RuntimeError("transient endpoint error")
        return super().chat(request)


def test_hypotheses_whose_sessions_failed_are_worked_by_the_next_run_and_the_failed_run_says_so(tmp_path):
    from romulus.agent.investigate import SESSIONS_FAILED_REASON, UNEXPLAINED_CLUSTERS, UNWORKED_HYPOTHESES
    s = Settings(home=tmp_path, agent_triage="off", agent_max_initial_hypotheses=1)
    repo = _hunt(tmp_path, s)
    failed = _run(s, repo, _Outage(_finish(), context=1_000_000))
    # the failed run is partial and names what it left: its failed hypotheses and the clusters never reached
    assert failed.state == "partial"
    assert SESSIONS_FAILED_REASON in failed.reason
    # one pending hypothesis (the top cluster's, retried once and failed again) and four clusters never reached
    assert f"{UNWORKED_HYPOTHESES}:1" in failed.reason and f"{UNEXPLAINED_CLUSTERS}:4" in failed.reason
    stranded = {row["id"] for row in _controller_rows(repo)}
    assert len(stranded) == 1

    healthy = _run(s, repo, _ByKind(_finish(), context=1_000_000))
    # the next run works the hypotheses the outage stranded (the top clusters), then the rest
    finished = {row["hypothesis_id"] for row in repo.agent_sessions("h1")
                if row["purpose"] == "investigate" and row["state"] == "finished"}
    assert stranded <= finished
    controller = _controller_rows(repo)
    assert [next(iter(_supported(repo, row))) for row in controller] == REPORT_ORDER
    assert unexplained_clusters(repo, "h1") == []
    assert UNWORKED_HYPOTHESES not in (healthy.reason or "") and UNEXPLAINED_CLUSTERS not in (healthy.reason or "")


def test_the_controller_keeps_opening_clusters_as_hypotheses_are_worked_up_to_the_initial_cap(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off", agent_max_initial_hypotheses=2)
    repo = _hunt(tmp_path, s)
    # orient opens nothing; the controller opens two at a time, as the pending ones are worked
    result = _run(s, repo, _ByKind(_finish(), context=1_000_000))

    assert result.state in {"completed", "partial"}
    controller = _controller_rows(repo)
    assert [next(iter(_supported(repo, row))) for row in controller] == REPORT_ORDER
    assert all(int(row["sessions_run"]) == 1 for row in controller)
    investigate = [row for row in repo.agent_sessions("h1") if row["purpose"] == "investigate"]
    assert len(investigate) == 5


def test_a_continuation_whose_hypotheses_are_all_worked_opens_the_unexplained_clusters(tmp_path):
    s = Settings(home=tmp_path, agent_triage="off")
    repo = _hunt(tmp_path, s)
    # a finished orient left two hypotheses, each worked to the per-hypothesis session cap
    repo.save_agent_session({"id": "as-orient", "hunt_id": "h1", "hypothesis_id": None, "purpose": "orient",
                             "state": "finished", "tool_calls": 1, "summary": "", "started_at": utcnow(),
                             "ended_at": utcnow()})
    admission = AgentAdmission(s, repo, "h1", "as-orient", purpose="orient")
    for finding_id in ("c-h3", "c-h2"):
        admission.create_controller_hypothesis(f"Earlier hypothesis on {finding_id}", finding_id=finding_id,
                                               alias=admission.aliases.alias_for("F", finding_id))
    from romulus.store import schema as t
    with repo.engine.begin() as connection:
        connection.execute(t.agent_hypothesis.update().where(t.agent_hypothesis.c.hunt_id == "h1").values(
            sessions_run=s.agent_max_sessions_per_hypothesis, questions=["still open"]))
    provider = _ByKind(_finish(), context=1_000_000)
    _run(s, repo, provider)

    # orient is not run again; the three clusters no hypothesis covered are opened and worked
    assert not any("Dossier index page" in str(request.messages[1]["content"]) for request in provider.requests)
    controller = [row for row in _controller_rows(repo) if not row["statement"].startswith("Earlier")]
    assert [next(iter(_supported(repo, row))) for row in controller] == ["c-h1", "c-l2", "c-l1"]
    assert all(int(row["sessions_run"]) == 1 for row in controller)


def test_a_hypothesis_is_worked_again_only_with_questions_left_or_after_an_unfinished_session(tmp_path):
    from romulus.agent.investigate import _pending
    s = Settings(home=tmp_path)
    repo = _hunt(tmp_path, s)
    now = utcnow()
    row = {"id": "hyp-x", "hunt_id": "h1", "statement": "A hypothesis under test", "techniques": [],
           "entity_ids": [], "status": "open", "confidence": "low", "questions": [], "created_session_id": None,
           "sessions_run": 0, "created_at": now, "updated_at": now}
    repo.save_agent_hypothesis(dict(row))
    assert _pending(s, row, repo)                                    # never worked
    row["sessions_run"] = 1
    repo.save_agent_session({"id": "as-1", "hunt_id": "h1", "hypothesis_id": "hyp-x", "purpose": "investigate",
                             "state": "budget", "tool_calls": 3, "summary": "", "started_at": utcnow(),
                             "ended_at": utcnow()})
    assert _pending(s, row, repo)                                    # its session was cut short by the budget
    repo.save_agent_session({"id": "as-2", "hunt_id": "h1", "hypothesis_id": "hyp-x", "purpose": "investigate",
                             "state": "finished", "tool_calls": 3, "summary": "", "started_at": utcnow(),
                             "ended_at": utcnow()})
    row["sessions_run"] = 2
    assert not _pending(s, row, repo)                                # finished with nothing left to ask
    for state, pending in (("failed", True), ("capped", True), ("context_full", True), ("interrupted", True),
                           ("refused", False), ("secret_guard", False)):
        session_id = f"as-{state}"
        repo.save_agent_session({"id": session_id, "hunt_id": "h1", "hypothesis_id": "hyp-x",
                                 "purpose": "investigate", "state": state, "tool_calls": 1, "summary": "",
                                 "started_at": utcnow(), "ended_at": utcnow()})
        row["sessions_run"] = 2
        assert _pending(s, row, repo) is pending, state
        with repo.engine.begin() as connection:     # this end is not the last one for the next state
            from romulus.store import schema as t
            connection.execute(t.agent_session.delete().where(t.agent_session.c.id == session_id))
    assert _pending(s, {**row, "questions": ["what next?"]}, repo)   # a question left keeps it in the rounds
    assert not _pending(s, {**row, "questions": ["q"], "sessions_run": s.agent_max_sessions_per_hypothesis}, repo)
    assert not _pending(s, {**row, "status": "supported", "sessions_run": 0}, repo)


def test_a_hypothesis_citing_a_clusters_evidence_explains_it(tmp_path):
    s = Settings(home=tmp_path)
    repo = _hunt(tmp_path, s, findings=())
    _candidate(repo, "c-a", "high", 2.0, event_ids=["ev-a"])
    _candidate(repo, "c-b", "high", 1.0, event_ids=["ev-b"])
    repo.save_agent_session({"id": "as-orient", "hunt_id": "h1", "hypothesis_id": None, "purpose": "orient",
                             "state": "finished", "tool_calls": 1, "summary": "", "started_at": utcnow(),
                             "ended_at": utcnow()})
    now = utcnow()
    repo.create_agent_hypothesis(
        {"id": "hyp-e", "hunt_id": "h1", "statement": "Evidence-led hypothesis", "techniques": [], "entity_ids": [],
         "status": "refuted", "confidence": "low", "questions": [], "created_session_id": "as-orient",
         "sessions_run": 1, "created_at": now, "updated_at": now},
        {"id": "he-e", "hunt_id": "h1", "hypothesis_id": "hyp-e", "session_id": "as-orient", "kind": "opened",
         "payload": {}, "created_at": now},
        [{"hunt_id": "h1", "hypothesis_id": "hyp-e", "role": "contradiction", "target_kind": "evidence",
          "target_id": "ev-a"}], max_count=40)
    view = hunt_clusters(repo, "h1")
    # any cite in any role and state explains a cluster: a refuted hypothesis still examined it
    assert cited_findings(repo, "h1", view) == {"c-a"}
    assert [cluster.top["id"] for cluster in unexplained_clusters(repo, "h1", view)] == ["c-b"]
    admission = AgentAdmission(s, repo, "h1", "as-orient", purpose="orient")
    assert _controller_open_hypotheses(s, repo, "h1", "as-orient", admission, view=view) == 1
    assert unexplained_clusters(repo, "h1", view) == []


def test_past_the_cluster_cap_the_view_is_partial_and_names_what_was_not_clustered(tmp_path, monkeypatch):
    monkeypatch.setattr(cluster_module, "CLUSTER_FINDING_LIMIT", 2)
    monkeypatch.setattr(cluster_module, "_PAGE", 2)
    repo = _hunt(tmp_path, Settings(home=tmp_path))
    view = hunt_clusters(repo, "h1")
    # the top of the lane and priority order is clustered; the rest is counted, never read as explained
    assert [cluster.top["id"] for cluster in view.clusters] == ["c-h3", "c-h2"]
    assert view.partial == {"reason": "cap:cluster_findings:2", "findings_not_clustered": 3}
