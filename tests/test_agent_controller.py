"""Resumable explicit investigator scheduling, budgets, and failure handling."""
import json
from datetime import UTC, datetime, timedelta

from romulus.agent.controller import Investigator
from romulus.agent.models import PivotResult
from romulus.agent.ollama import ModelResult, ModelUnavailable
from romulus.config import Settings
from romulus.evidence.typed import TypedEvent
from romulus.sources.models import Window
from romulus.store.db import digest, make_engine, migrate
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


def _evidence(repo: Repo, event_id: str, ts: datetime) -> None:
    repo.save_evidence("h1", [TypedEvent(
        id=event_id, family="process_exec", ts=ts, host="video",
        fields={}, raw=[], normalizer="test@1",
    )], {}, None)


def _result(parsed: dict, *, duration=5) -> ModelResult:
    return ModelResult(
        ok=True, status="ok", raw=json.dumps(parsed), parsed=parsed, prompt_tokens_est=100,
        prompt_eval_count=90, eval_count=20, duration_ms=duration,
    )


def _selection(option="O1", evidence="E1", rationale="Cited evidence supports this option.") -> dict:
    return {"option": option, "evidence": [evidence], "rationale": rationale}


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
        self.users = []
        self.requests = []

    def chat_json(self, *_args, **_kwargs):
        self.calls += 1
        self.users.append(_args[2])
        self.requests.append({"system": _args[1], "user": _args[2], "schema": _args[3]})
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            item = item(_args[2])
        return item


def _choose_description(needle: str, evidence: str = "E1"):
    def choose(user: str) -> ModelResult:
        payload = json.loads(user.split("<UNTRUSTED_TELEMETRY>\n", 1)[1].split(
            "\n</UNTRUSTED_TELEMETRY>", 1,
        )[0])
        option = next(item for item in payload["menu"] if needle in item["description"])
        return _result(_selection(option["id"], evidence))
    return choose


def test_prompt_digest_covers_system_user_and_schema():
    repo = _repo(total=1)
    _candidate(repo, "c1", "video", 50)
    model = QueueModel([_result({
        "action": "close", "evidence_ids": ["event-c1"], "reasoning": "Routine activity.",
    })])

    _investigator(repo, model, RecordingExecutor()).run()

    assert repo.model_calls(hunt_id="h1")[0]["prompt_digest"] == digest(model.requests[0])


class RecordingExecutor:
    def __init__(self):
        self.calls = []
        self.anchors = []

    def run(self, case_id, request, *, anchor_ts=None):
        self.calls.append((case_id, request.tool))
        self.anchors.append(anchor_ts)
        return PivotResult(status="complete", task_ids=[f"task-{case_id}"], duration_ms=10)


def _investigator(repo, model, executor, **kwargs):
    return Investigator(
        Settings(ollama_num_ctx=4096), repo, executor, "h1", WINDOW,
        model_client=model, **kwargs,
    )


def test_deterministic_mode_uses_top_pivots_without_model_calls_and_is_reproducible():
    decisions = []
    for _index in range(2):
        repo = _repo(total=1, per_case=4)
        _candidate(repo, "c1", "video", 50)
        _evidence(repo, "event-c1", START)
        model = QueueModel([])
        executor = RecordingExecutor()

        summary = _investigator(repo, model, executor, agent_mode="deterministic").run()

        case = repo.cases("h1")[0]
        step = repo.case_steps(case["id"])[1]
        assert summary["mode"] == "deterministic"
        assert model.calls == 0
        assert len(executor.calls) == 1
        assert step["decision"]["agent_mode"] == "deterministic"
        assert step["decision"]["chosen_option"] == "O1"
        assert step["decision"]["menu"] and step["decision"]["aliases"]["evidence"] == {"E1": "event-c1"}
        decisions.append(step["decision"])
    assert decisions[0] == decisions[1]


def test_deterministic_mode_parks_with_completion_reason_when_no_pivot_remains():
    repo = _repo(total=1, per_case=1)
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "test.rule", "rule_version": "1",
        "claim": "Suspicious domain.", "claim_type": "observed_action",
        "event_ids": ["event-c1"], "predicate_fields": [],
        "entities": [["domain", "example.test", "destination"]], "ts": START,
        "severity": "medium", "confidence": "high", "lane": "lead", "priority": 50,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None,
    })
    _evidence(repo, "event-c1", START)
    model = QueueModel([])

    summary = _investigator(
        repo, model, RecordingExecutor(), agent_mode="deterministic",
    ).run()

    case = repo.cases("h1")[0]
    decision = repo.case_steps(case["id"])[1]["decision"]
    assert summary["status"] == "completed" and case["status"] == "parked"
    assert decision["action"] == "park_as_lead"
    assert decision["reasoning"] == "deterministic investigation complete"
    assert model.calls == 0


def test_model_mode_falls_back_to_top_pivot_after_two_constraint_defects():
    repo = _repo(total=3, per_case=3)
    _candidate(repo, "c1", "video", 50)
    _evidence(repo, "event-c1", START)
    model = QueueModel([_result(_selection("O999")), _result(_selection("O999"))])
    executor = RecordingExecutor()

    summary = _investigator(repo, model, executor, agent_mode="model").run()

    case = repo.cases("h1")[0]
    steps = repo.case_steps(case["id"])[1:]
    assert model.calls == 2 and len(executor.calls) == 1
    assert [step["accepted"] for step in steps] == [0, 0, 1]
    assert all(step["rejection"].startswith("unknown option") for step in steps[:2])
    assert steps[2]["decision"]["deterministic_fallback"] is True
    assert "failed twice" in steps[2]["decision"]["fallback_note"]
    assert summary["deterministic_fallbacks"] == 1
    assert summary["constraint_defects"] == 2


def test_model_mode_fallback_parks_only_when_no_pivot_option_remains():
    repo = _repo(total=3, per_case=3)
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "test.rule", "rule_version": "1",
        "claim": "Suspicious domain.", "claim_type": "observed_action",
        "event_ids": ["event-c1"], "predicate_fields": [],
        "entities": [["domain", "example.test", "destination"]], "ts": START,
        "severity": "medium", "confidence": "high", "lane": "lead", "priority": 50,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None,
    })
    _evidence(repo, "event-c1", START)
    model = QueueModel([_result(_selection("O999")), _result(_selection("O999"))])

    summary = _investigator(repo, model, RecordingExecutor(), agent_mode="model").run()

    case = repo.cases("h1")[0]
    final = repo.case_steps(case["id"])[-1]["decision"]
    assert case["status"] == "fallback_parked"
    assert final["action"] == "park_as_lead" and final["deterministic_fallback"] is True
    assert summary["fallback_parked_count"] == 1


def test_scheduler_gives_each_case_one_call_before_depth():
    repo = _repo(total=2, per_case=4)
    _candidate(repo, "c-high", "video", 80)
    _candidate(repo, "c-low", "control", 20)
    _evidence(repo, "event-c-high", START)
    _evidence(repo, "event-c-low", START)
    model = QueueModel([
        _result(_selection()),
        _result(_selection()),
    ])
    executor = RecordingExecutor()

    summary = _investigator(repo, model, executor).run()

    assert summary["status"] == "budget_exhausted"
    assert len({case_id for case_id, _tool in executor.calls}) == 2
    assert [case["steps_used"] for case in repo.cases("h1")] == [1, 1]


def test_accepted_pivot_receives_anchor_from_cited_persisted_evidence():
    repo = _repo(total=1)
    _candidate(repo, "c1", "video", 50)
    anchor = START + timedelta(minutes=2)
    _evidence(repo, "event-c1", anchor)
    model = QueueModel([_result(_selection())])
    executor = RecordingExecutor()

    _investigator(repo, model, executor).run()

    assert executor.anchors == [anchor]


def test_two_rejections_count_against_budget_without_unsafe_parking():
    repo = _repo(total=4, per_case=2)
    _candidate(repo, "c1", "video", 50)
    model = QueueModel([_result(_selection("O999")), _result(_selection("O999"))])

    summary = _investigator(repo, model, RecordingExecutor()).run()

    case = repo.cases("h1")[0]
    assert summary["status"] == "budget_exhausted"
    assert case["status"] == "budget_exhausted"
    assert case["steps_used"] == 2
    assert [step["accepted"] for step in repo.case_steps(case["id"])[1:]] == [0, 0]
    assert summary["unworked_seed_ids"] == ["c1"]
    assert summary["unworked_count"] == 1
    assert summary["fallback_parked_count"] == 0


def test_retry_never_exceeds_the_per_case_step_budget():
    repo = _repo(total=4, per_case=1)
    _candidate(repo, "c1", "video", 50)
    _evidence(repo, "event-c1", START)
    model = QueueModel([_result(_selection("O999")), _result(_selection("O999"))])

    summary = _investigator(repo, model, RecordingExecutor()).run()

    case = repo.cases("h1")[0]
    assert summary["status"] == "budget_exhausted"
    assert model.calls == 1
    assert case["steps_used"] == 1
    assert len(repo.case_steps(case["id"])[1:]) == 1


def test_spawn_is_bounded_by_max_cases():
    repo = _repo(total=2, max_cases=2)
    repo.save_candidate({
        "id": "c1", "hunt_id": "h1", "rule_id": "test.rule", "rule_version": "1",
        "claim": "Suspicious domain.", "claim_type": "observed_action",
        "event_ids": ["event-c1"], "predicate_fields": [],
        "entities": [["domain", "example.test", "destination"]], "ts": START,
        "severity": "medium", "confidence": "high", "lane": "lead", "priority": 50,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None,
    })
    _evidence(repo, "event-c1", START)
    model = QueueModel([_choose_description("spawn a case for ip 203.0.113.8")])
    investigator = _investigator(repo, model, RecordingExecutor())
    investigator._seed_cases()
    case = repo.cases("h1")[0]
    repo.append_case_step(
        case["id"], 1, {"action": "pivot"}, True,
        result_digest={
            "status": "complete", "entities": [{"kind": "ip", "value": "203.0.113.8", "role": "dst"}],
        },
    )
    repo.update_case(case["id"], steps_used=1)

    investigator.run()

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


def test_resume_repartitions_a_legacy_oversized_open_seed_case():
    repo = _repo(total=1, per_case=1, max_cases=4)
    for index in range(10):
        _candidate(
            repo, f"c{index:02}", "video", 100 - index,
            ip="203.0.113.99" if index == 9 else None,
        )
    seed_ids = [f"c{index:02}" for index in range(10)]
    repo.create_case({
        "id": "legacy-case", "hunt_id": "h1", "seed_candidate_id": seed_ids[0],
        "title": "legacy oversized case", "priority": 999,
        "entities": [["host", "video", "host"], ["ip", "203.0.113.99", "src"]],
        "hypotheses": [], "step_budget": 1,
    })
    repo.append_case_step(
        "legacy-case", 0, {"action": "seed", "seed_candidate_ids": seed_ids}, True,
    )
    repo.append_case_step(
        "legacy-case", 1, {"action": "pivot"}, True,
        result_digest={
            "status": "complete",
            "entities": [{"kind": "domain", "value": "pivot.test", "role": "destination"}],
        },
    )

    investigator = _investigator(
        repo, QueueModel([]), RecordingExecutor(), agent_mode="deterministic",
    )
    investigator._seed_cases()

    groups = [investigator._seed_ids(repo.case_steps(case["id"])) for case in repo.cases("h1")]
    legacy_steps = repo.case_steps("legacy-case")
    assert legacy_steps[0]["decision"]["seed_candidate_ids"] == seed_ids
    assert legacy_steps[-1]["decision"] == {
        "action": "seed_partition",
        "seed_candidate_ids": seed_ids[:9],
        "previous_seed_count": 10,
    }
    legacy_case = repo.case("legacy-case")
    assert legacy_case["priority"] == 100
    assert legacy_case["entities"] == [
        {"kind": "host", "value": "video", "role": "host"},
        {"kind": "domain", "value": "pivot.test", "role": "destination"},
    ]
    assert sorted(len(group) for group in groups) == [1, 9]
    assert sorted(candidate_id for group in groups for candidate_id in group) == seed_ids


def test_resume_replays_persisted_v2_pivot_without_a_result_before_new_model_calls():
    repo = _repo(total=1)
    _candidate(repo, "c1", "video", 50)
    anchor = START + timedelta(minutes=2)
    _evidence(repo, "event-c1", anchor)
    case_id = "case-existing"
    repo.create_case({
        "id": case_id, "hunt_id": "h1", "seed_candidate_id": "c1", "title": "existing",
        "priority": 50, "entities": [["host", "video", "host"]], "hypotheses": [], "step_budget": 4,
        "steps_used": 1,
    })
    repo.append_case_step(case_id, 0, {"action": "seed", "seed_candidate_ids": ["c1"]}, True)
    decision = _host_pivot("video", "event-c1")
    decision.update({
        "chosen_option": "O1",
        "option_description": "entity_timeline for host video, anchor ±5 min",
        "menu": [{"id": "O1", "description": "entity_timeline for host video, anchor ±5 min"}],
        "menu_hidden_count": 2,
        "aliases": {"evidence": {"E1": "event-c1"}},
        "agent_mode": "model",
        "deterministic_fallback": False,
    })
    repo.append_case_step(case_id, 1, decision, True, task_id="pending-pivot")
    executor = RecordingExecutor()
    model = QueueModel([])

    summary = _investigator(repo, model, executor).run()

    assert executor.calls == [(case_id, "entity_timeline")]
    assert executor.anchors == [anchor]
    assert repo.case_steps(case_id)[1]["result_digest"]["status"] == "complete"
    assert model.calls == 0
    assert summary["status"] == "budget_exhausted"


def test_executed_pivot_is_removed_from_the_next_generated_menu():
    repo = _repo(total=3, per_case=3)
    _candidate(repo, "c1", "video", 50)
    _evidence(repo, "event-c1", START)
    model = QueueModel([
        _result(_selection()), _result(_selection("O999")), _result(_selection("O999")),
    ])
    executor = RecordingExecutor()

    summary = _investigator(repo, model, executor).run()

    case = repo.cases("h1")[0]
    proposal_steps = repo.case_steps(case["id"])[1:]
    assert len(executor.calls) == 1
    assert case["steps_used"] == 3
    assert case["status"] == "budget_exhausted"
    assert [step["accepted"] for step in proposal_steps] == [1, 0, 0]
    executed = proposal_steps[0]["decision"]
    for rejected in proposal_steps[1:]:
        assert not any(
            option["decision"].get("tool") == executed["tool"]
            and option["decision"].get("arguments") == executed["arguments"]
            for option in rejected["decision"]["menu"]
        )
    assert summary["duplicate_pivots_blocked"] == 0


def test_model_cannot_mutate_the_controller_owned_option_payload():
    repo = _repo(total=2, per_case=2)
    _candidate(repo, "c1", "video", 50)
    _evidence(repo, "event-c1", START)
    mutated = {**_selection(), "arguments": {"query": {"match_all": {}}}}
    model = QueueModel([_result(mutated), _result(mutated)])
    executor = RecordingExecutor()

    summary = _investigator(repo, model, executor).run()

    case = repo.cases("h1")[0]
    assert executor.calls == []
    assert summary["constraint_defects"] == 2
    assert case["status"] == "budget_exhausted"
