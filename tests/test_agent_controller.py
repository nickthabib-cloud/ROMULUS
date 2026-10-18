"""Resumable explicit investigator scheduling, budgets, and failure handling."""
import json
from datetime import UTC, datetime, timedelta

from romulus.agent.controller import Investigator
from romulus.agent.models import PivotResult
from romulus.agent.ollama import ModelResult, ModelUnavailable
from romulus.config import Settings
from romulus.sources.models import Window
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
WINDOW = Window(start=START, end=START + timedelta(hours=1))


def _repo(*, total=6, per_case=4, max_cases=4, wall_minutes=120) -> Repo:
    engine = make_engine(":memory:")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h1", {
        "window": {"start": WINDOW.start.isoformat(), "end": WINDOW.end.isoformat()},
        "budgets": {
            "agent_steps_total": total, "agent_steps_per_case": per_case,
            "max_cases": max_cases, "wall_clock_minutes": wall_minutes,
        },
    }, "digest", "test")
    return repo


def _candidate(repo: Repo, cid: str, host: str, priority: float, *, ip: str | None = None):
    entities = [["host", host, "host"]]
    if ip:
        entities.append(["ip", ip, "src"])
    repo.save_candidate({
        "id": cid, "hunt_id": "h1", "rule_id": "test.rule", "rule_version": "1",
        "claim": f"Suspicious action on {host}.", "claim_type": "observed_action",
        "event_ids": [f"event-{cid}"], "predicate_fields": [], "entities": entities, "ts": START,
        "severity": "medium", "confidence": "high", "lane": "lead", "priority": priority,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None,
    })


def _result(parsed: dict, *, duration=5) -> ModelResult:
    return ModelResult(
        ok=True, status="ok", raw=json.dumps(parsed), parsed=parsed, prompt_tokens_est=100,
        prompt_eval_count=90, eval_count=20, duration_ms=duration,
    )


def _host_pivot(host: str, evidence: str) -> dict:
    return {
        "action": "pivot", "tool": "entity_timeline",
        "arguments": {
            "entity": {"kind": "host", "value": host, "role": "host"},
            "start": START.isoformat(), "end": (START + timedelta(minutes=10)).isoformat(),
        },
        "hypothesis": "Related host activity exists.", "expected_true": "Events are returned.",
        "expected_false": "No events are returned.", "evidence_ids": [evidence],
    }


class QueueModel:
    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def chat_json(self, *_args, **_kwargs):
        self.calls += 1
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    def run(self, case_id, request):
        self.calls.append((case_id, request.tool))
        return PivotResult(status="complete", task_ids=[f"task-{case_id}"], duration_ms=10)


def _investigator(repo, model, executor, **kwargs):
    return Investigator(
        Settings(ollama_num_ctx=4096), repo, executor, "h1", WINDOW,
        model_client=model, **kwargs,
    )


def test_scheduler_gives_each_case_one_call_before_depth():
    repo = _repo(total=2, per_case=4)
    _candidate(repo, "c-high", "video", 80)
    _candidate(repo, "c-low", "control", 20)
    model = QueueModel([
        _result(_host_pivot("video", "event-c-high")),
        _result(_host_pivot("control", "event-c-low")),
    ])
    executor = RecordingExecutor()

    summary = _investigator(repo, model, executor).run()

    assert summary["status"] == "budget_exhausted"
    assert len({case_id for case_id, _tool in executor.calls}) == 2
    assert [case["steps_used"] for case in repo.cases("h1")] == [1, 1]


def test_two_rejections_count_against_budget_then_park_deterministically():
    repo = _repo(total=4, per_case=2)
    _candidate(repo, "c1", "video", 50)
    invalid = _host_pivot("video", "event-c1")
    invalid["arguments"]["query"] = {"match_all": {}}
    model = QueueModel([_result(invalid), _result(invalid)])

    summary = _investigator(repo, model, RecordingExecutor()).run()

    case = repo.cases("h1")[0]
    assert summary["status"] == "completed"
    assert case["status"] == "parked"
    assert case["steps_used"] == 2
    assert [step["accepted"] for step in repo.case_steps(case["id"])[1:]] == [0, 0]
    assert "validation failed twice" in case["summary"]


def test_spawn_is_bounded_by_max_cases():
    repo = _repo(total=1, max_cases=2)
    _candidate(repo, "c1", "video", 50, ip="203.0.113.8")
    model = QueueModel([_result({
        "action": "spawn", "entity": {"kind": "ip", "value": "203.0.113.8", "role": "src"},
        "evidence_ids": ["event-c1"], "reasoning": "Separate the network thread.",
    })])

    _investigator(repo, model, RecordingExecutor()).run()

    cases = repo.cases("h1")
    assert len(cases) == 2
    assert sum(case["seed_candidate_id"] is None for case in cases) == 1


def test_every_unworked_seed_is_reported_when_case_budget_is_smaller_than_seed_set():
    repo = _repo(total=0, max_cases=1)
    for index, host in enumerate(("alpha", "bravo", "charlie")):
        _candidate(repo, f"c{index}", host, 30 - index)

    summary = _investigator(repo, QueueModel([]), RecordingExecutor()).run()

    assert summary["status"] == "budget_exhausted"
    assert len(summary["assigned_unfinished_seed_ids"]) == 1
    assert len(summary["unassigned_seed_ids"]) == 2
    assert set(summary["unworked_seed_ids"]) == {"c0", "c1", "c2"}


def test_persisted_elapsed_time_exhausts_wall_clock_on_resume():
    repo = _repo(total=5, wall_minutes=1)
    _candidate(repo, "c1", "video", 50)
    repo.save_model_call({
        "id": "old", "hunt_id": "h1", "case_id": None, "purpose": "triage", "model": "test",
        "options": {}, "prompt_digest": "p", "duration_ms": 60_001, "status": "ok", "at": START,
    })
    model = QueueModel([])

    summary = _investigator(repo, model, RecordingExecutor(), clock=lambda: 0.0).run()

    assert summary["status"] == "budget_exhausted"
    assert model.calls == 0
    assert "wall-clock" in summary["stop_reason"]


def test_model_outage_leaves_case_open_for_resume():
    repo = _repo()
    _candidate(repo, "c1", "video", 50)
    model = QueueModel([ModelUnavailable("connection refused")])

    summary = _investigator(repo, model, RecordingExecutor()).run()

    assert summary["status"] == "unavailable"
    assert summary["partial"] is True
    assert repo.cases("h1")[0]["status"] == "open"


def test_resume_replays_accepted_pivot_without_a_result_before_new_model_calls():
    repo = _repo(total=1)
    _candidate(repo, "c1", "video", 50)
    case_id = "case-existing"
    repo.create_case({
        "id": case_id, "hunt_id": "h1", "seed_candidate_id": "c1", "title": "existing",
        "priority": 50, "entities": [["host", "video", "host"]], "hypotheses": [], "step_budget": 4,
        "steps_used": 1,
    })
    repo.append_case_step(case_id, 0, {"action": "seed", "seed_candidate_ids": ["c1"]}, True)
    decision = _host_pivot("video", "event-c1")
    repo.append_case_step(case_id, 1, decision, True, task_id="pending-pivot")
    executor = RecordingExecutor()
    model = QueueModel([])

    summary = _investigator(repo, model, executor).run()

    assert executor.calls == [(case_id, "entity_timeline")]
    assert repo.case_steps(case_id)[1]["result_digest"]["status"] == "complete"
    assert model.calls == 0
    assert summary["status"] == "budget_exhausted"
