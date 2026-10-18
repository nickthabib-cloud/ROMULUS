"""Explicit, bounded, resumable model-investigation controller."""
from __future__ import annotations

import json
from collections.abc import Callable
from time import monotonic
from typing import Any

from pydantic import ValidationError

from romulus.agent.brief import build_brief
from romulus.agent.cases import cluster_seed_candidates
from romulus.agent.models import AgentDecision, EntityRef, PivotResult
from romulus.agent.ollama import ModelResult, ModelUnavailable, OllamaClient
from romulus.agent.tools import parse_tool_request, tool_schema
from romulus.agent.validate import ValidationResult, validate_decision
from romulus.config import Settings
from romulus.store.db import digest, utcnow
from romulus.store.repo import Repo

_CONCLUDED = {"closed", "parked", "escalated"}
_UNFINISHED = {"open", "budget_exhausted"}


class Investigator:
    def __init__(self, settings: Settings, repo: Repo, pivot_executor: Any, hunt_id: str,
                 window: Any, model_client: Any | None = None,
                 heartbeat: Callable[[], None] | None = None,
                 clock: Callable[[], float] | None = None):
        self.settings = settings
        self.repo = repo
        self.pivot_executor = pivot_executor
        self.hunt_id = hunt_id
        self.window = window
        self.model = model_client or OllamaClient(settings)
        self.heartbeat = heartbeat or (lambda: None)
        self.clock = clock or monotonic
        hunt = repo.get_hunt(hunt_id)
        if hunt is None:
            raise KeyError(hunt_id)
        self.budgets = hunt["manifest"].get("budgets") or {}
        self.total_budget = int(self.budgets.get("agent_steps_total", 60))
        self.per_case_budget = int(self.budgets.get("agent_steps_per_case", 8))
        self.max_cases = int(self.budgets.get("max_cases", 12))
        self.wall_budget_ms = int(float(self.budgets.get("wall_clock_minutes", 120)) * 60_000)
        self.persisted_elapsed_ms = repo.agent_elapsed_ms(hunt_id)
        self.run_started = self.clock()
        self.partial_pivot = any(
            (step.get("result_digest") or {}).get("status") in {"partial", "failed"}
            for case in repo.cases(hunt_id) for step in repo.case_steps(case["id"])
        )

    def _wall_exhausted(self) -> bool:
        current_ms = max(0, int((self.clock() - self.run_started) * 1000))
        return self.persisted_elapsed_ms + current_ms >= self.wall_budget_ms

    def _total_steps(self) -> int:
        return sum(int(case["steps_used"]) for case in self.repo.cases(self.hunt_id))

    @staticmethod
    def _seed_ids(steps: list[dict]) -> list[str]:
        for step in steps:
            decision = step.get("decision") or {}
            if step["n"] == 0 and decision.get("action") == "seed":
                return list(decision.get("seed_candidate_ids") or [])
        return []

    def _seed_cases(self) -> list[str]:
        candidates = [
            candidate for candidate in self.repo.candidates(self.hunt_id)
            if candidate["lane"] != "context" and candidate.get("source_case_id") is None
        ]
        all_seed_ids = [candidate["id"] for candidate in candidates]
        assigned = {
            seed_id
            for case in self.repo.cases(self.hunt_id)
            for seed_id in self._seed_ids(self.repo.case_steps(case["id"]))
        }
        for cluster in cluster_seed_candidates(candidates):
            if assigned.intersection(cluster.seed_candidate_ids):
                continue
            if len(self.repo.cases(self.hunt_id)) >= self.max_cases:
                continue
            primary = cluster.primary_entity
            subject = f"{primary.kind}:{primary.value}" if primary else cluster.seed_candidate_ids[0]
            created = self.repo.create_case({
                "id": cluster.id,
                "hunt_id": self.hunt_id,
                "seed_candidate_id": cluster.seed_candidate_ids[0],
                "title": f"Investigate {subject}",
                "priority": cluster.priority,
                "entities": [entity.model_dump(mode="json") for entity in cluster.entities],
                "hypotheses": [],
                "step_budget": self.per_case_budget,
            })
            if created:
                self.repo.append_case_step(
                    cluster.id, 0,
                    {"action": "seed", "seed_candidate_ids": cluster.seed_candidate_ids},
                    True,
                )
                assigned.update(cluster.seed_candidate_ids)
        return all_seed_ids

    def _next_step_number(self, case_id: str) -> int:
        steps = self.repo.case_steps(case_id)
        return max((step["n"] for step in steps), default=0) + 1

    def _record_call(self, case: dict, step_n: int, brief, result: ModelResult,
                     validation: ValidationResult | None, status: str | None = None) -> str:
        call_id = "mc-" + digest({"hunt": self.hunt_id, "case": case["id"], "step": step_n})[:20]
        validation_data = None if validation is None else {
            "ok": validation.ok, "errors": validation.errors,
        }
        self.repo.save_model_call({
            "id": call_id,
            "hunt_id": self.hunt_id,
            "case_id": case["id"],
            "purpose": "triage",
            "model": self.settings.ollama_model_triage,
            "options": {
                "num_ctx": self.settings.ollama_num_ctx, "max_out": 900,
                "think": self.settings.ollama_think, "shrink_actions": brief.shrink_actions,
            },
            "prompt_digest": digest({"system": brief.system, "user": brief.user}),
            "prompt_tokens_est": result.prompt_tokens_est,
            "prompt_eval_count": result.prompt_eval_count,
            "eval_count": result.eval_count,
            "duration_ms": result.duration_ms,
            "raw_response": result.raw,
            "parsed": result.parsed,
            "validation": validation_data,
            "status": status or result.status,
            "at": utcnow(),
        })
        return call_id

    def _record_exception(self, case: dict, step_n: int, brief, error: str) -> None:
        result = ModelResult(
            ok=False, status="error", raw="", parsed=None,
            prompt_tokens_est=brief.token_estimate, prompt_eval_count=None, eval_count=None,
            duration_ms=0, error=error,
        )
        call_id = self._record_call(case, step_n, brief, result, None)
        self.repo.append_case_step(
            case["id"], step_n, {"action": "model_error", "error": error}, False,
            rejection=error, model_call_id=call_id,
        )
        self.repo.update_case(case["id"], steps_used=int(case["steps_used"]) + 1)

    def _call_once(self, case: dict, retry_errors: tuple[str, ...]) -> tuple[str, Any]:
        step_n = self._next_step_number(case["id"])
        brief = build_brief(
            self.repo, case["id"], tool_schema(), self.settings.ollama_num_ctx,
            retry_errors=retry_errors,
        )
        try:
            result = self.model.chat_json(
                self.settings.ollama_model_triage, brief.system, brief.user,
                AgentDecision.model_json_schema(), max_out=900,
            )
        except ModelUnavailable as exc:
            self._record_exception(case, step_n, brief, str(exc))
            return "unavailable", str(exc)

        if not result.ok and result.status in {"truncated", "too_large", "error"}:
            call_id = self._record_call(case, step_n, brief, result, None)
            self.repo.append_case_step(
                case["id"], step_n, {"action": "model_error", "status": result.status}, False,
                rejection=result.error, model_call_id=call_id,
            )
            self.repo.update_case(case["id"], steps_used=int(case["steps_used"]) + 1)
            return "unavailable", result.error or result.status

        decision = None
        validation = None
        parse_errors: list[str] = []
        try:
            decision = AgentDecision.model_validate(result.parsed)
        except ValidationError as exc:
            parse_errors = [f"invalid decision schema: {exc}"]
        if decision is not None:
            validation = validate_decision(decision, brief, self.window)
            parse_errors = validation.errors
        accepted = bool(validation and validation.ok)
        result_status = result.status if accepted else "invalid"
        call_id = self._record_call(case, step_n, brief, result, validation, status=result_status)
        stored_decision = decision.model_dump(mode="json") if decision else (result.parsed or {"action": "invalid"})
        pending_id = None
        if accepted and decision.action == "pivot":
            pending_id = "pending-" + digest({"case": case["id"], "step": step_n, "decision": stored_decision})[:20]
        self.repo.append_case_step(
            case["id"], step_n, stored_decision, accepted,
            rejection="; ".join(parse_errors) if parse_errors else None,
            model_call_id=call_id, task_id=pending_id,
        )
        self.repo.update_case(case["id"], steps_used=int(case["steps_used"]) + 1)
        self.heartbeat()
        if not accepted:
            return "rejected", parse_errors
        return "accepted", (decision, validation, step_n)

    def _merge_entities(self, case: dict, discovered: list[EntityRef]) -> list[dict]:
        current = []
        for entity in case.get("entities") or []:
            if isinstance(entity, (list, tuple)) and len(entity) >= 3:
                current.append(EntityRef(kind=entity[0], value=str(entity[1]), role=str(entity[2])))
            else:
                current.append(EntityRef.model_validate(entity))
        unique = {(entity.kind, entity.value, entity.role): entity for entity in current + discovered}
        return [entity.model_dump(mode="json") for entity in unique.values()]

    @staticmethod
    def _conclusion(decision: AgentDecision) -> str:
        return json.dumps({
            "model_conclusion": decision.action,
            "candidate_id": decision.candidate_id,
            "reasoning": decision.reasoning,
            "evidence_ids": decision.evidence_ids,
            "benign_alternatives": decision.benign_alternatives,
            "resolution_needed": decision.resolution_needed,
        }, sort_keys=True)

    def _execute_action(self, case: dict, decision: AgentDecision,
                        validation: ValidationResult, step_n: int) -> None:
        if decision.action == "pivot":
            result: PivotResult = self.pivot_executor.run(case["id"], validation.request)
            self.partial_pivot |= result.status in {"partial", "failed"}
            self.repo.update_case_step(
                case["id"], step_n,
                task_id=result.task_ids[0] if result.task_ids else None,
                result_digest=result.model_dump(mode="json"),
            )
            hypotheses = list(case.get("hypotheses") or [])
            if decision.hypothesis and decision.hypothesis not in hypotheses:
                hypotheses.append(decision.hypothesis)
            self.repo.update_case(
                case["id"], hypotheses=hypotheses,
                entities=self._merge_entities(case, result.entities),
            )
        elif decision.action == "escalate":
            self.repo.update_case(case["id"], status="escalated", summary=self._conclusion(decision))
        elif decision.action == "close":
            self.repo.update_case(case["id"], status="closed", summary=self._conclusion(decision))
        elif decision.action == "park_as_lead":
            self.repo.update_case(case["id"], status="parked", summary=self._conclusion(decision))
        elif decision.action == "spawn" and decision.entity is not None:
            if len(self.repo.cases(self.hunt_id)) < self.max_cases:
                child_id = "case-" + digest({
                    "parent": case["id"], "entity": decision.entity.model_dump(mode="json"),
                })[:16]
                created = self.repo.create_case({
                    "id": child_id, "hunt_id": self.hunt_id, "seed_candidate_id": None,
                    "title": f"Investigate {decision.entity.kind}:{decision.entity.value}",
                    "priority": max(0.0, float(case["priority"]) - 0.01),
                    "entities": [decision.entity.model_dump(mode="json")], "hypotheses": [],
                    "step_budget": self.per_case_budget,
                })
                if created:
                    self.repo.append_case_step(
                        child_id, 0,
                        {"action": "spawn_seed", "parent_case_id": case["id"],
                         "evidence_ids": decision.evidence_ids},
                        True,
                    )

    def _replay_pending(self) -> None:
        for step in self.repo.pending_case_steps(self.hunt_id):
            decision = AgentDecision.model_validate(step["decision"])
            request = parse_tool_request(decision)
            result: PivotResult = self.pivot_executor.run(step["case_id"], request)
            self.partial_pivot |= result.status in {"partial", "failed"}
            self.repo.update_case_step(
                step["case_id"], step["n"],
                task_id=result.task_ids[0] if result.task_ids else step["task_id"],
                result_digest=result.model_dump(mode="json"),
            )
            case = self.repo.case(step["case_id"])
            if case is not None:
                hypotheses = list(case.get("hypotheses") or [])
                if decision.hypothesis and decision.hypothesis not in hypotheses:
                    hypotheses.append(decision.hypothesis)
                self.repo.update_case(
                    case["id"], hypotheses=hypotheses,
                    entities=self._merge_entities(case, result.entities),
                )
            self.heartbeat()

    def _mark_budget_exhausted(self) -> None:
        for case in self.repo.cases(self.hunt_id, statuses=["open"]):
            self.repo.update_case(case["id"], status="budget_exhausted")

    def _summary(self, status: str, reason: str, all_seed_ids: list[str], partial: bool = False) -> dict:
        cases = self.repo.cases(self.hunt_id)
        concluded: set[str] = set()
        unfinished: set[str] = set()
        assigned: set[str] = set()
        for case in cases:
            seeds = set(self._seed_ids(self.repo.case_steps(case["id"])))
            assigned.update(seeds)
            if case["status"] in _CONCLUDED:
                concluded.update(seeds)
            elif case["status"] in _UNFINISHED:
                unfinished.update(seeds)
        unassigned = set(all_seed_ids) - assigned
        unworked = unfinished | unassigned
        calls = self.repo.model_calls(hunt_id=self.hunt_id)
        pivot_steps = [
            step for case in cases for step in self.repo.case_steps(case["id"])
            if (step.get("decision") or {}).get("action") == "pivot" and step.get("accepted")
        ]
        return {
            "status": status,
            "partial": partial or self.partial_pivot,
            "stop_reason": reason,
            "cases_total": len(cases),
            "seed_count": len(all_seed_ids),
            "concluded_seed_ids": sorted(concluded),
            "assigned_unfinished_seed_ids": sorted(unfinished),
            "unassigned_seed_ids": sorted(unassigned),
            "unworked_seed_ids": sorted(unworked),
            "unworked_count": len(unworked),
            "model_calls": len(calls),
            "pivots": len(pivot_steps),
        }

    def run(self) -> dict:
        all_seed_ids = self._seed_cases()
        self._replay_pending()
        if not self.repo.cases(self.hunt_id, statuses=["open"]):
            return self._summary("completed", "all selected cases concluded", all_seed_ids)

        while True:
            open_cases = self.repo.cases(self.hunt_id, statuses=["open"])
            if not open_cases:
                return self._summary("completed", "all selected cases concluded", all_seed_ids)
            if self._wall_exhausted():
                self._mark_budget_exhausted()
                return self._summary("budget_exhausted", "agent wall-clock budget exhausted", all_seed_ids)
            if self._total_steps() >= self.total_budget:
                self._mark_budget_exhausted()
                return self._summary("budget_exhausted", "agent total-step budget exhausted", all_seed_ids)

            for case in open_cases:
                if int(case["steps_used"]) >= min(int(case["step_budget"]), self.per_case_budget):
                    self.repo.update_case(case["id"], status="budget_exhausted")
            open_cases = self.repo.cases(self.hunt_id, statuses=["open"])
            if not open_cases:
                return self._summary("budget_exhausted", "all open cases exhausted their step budgets", all_seed_ids)

            case = min(open_cases, key=lambda item: (int(item["steps_used"]), -float(item["priority"]), item["id"]))
            retry_errors: tuple[str, ...] = ()
            rejected = 0
            while True:
                case = self.repo.case(case["id"])
                if case is None:
                    break
                if self._wall_exhausted() or self._total_steps() >= self.total_budget:
                    break
                outcome, value = self._call_once(case, retry_errors)
                if outcome == "unavailable":
                    return self._summary(
                        "unavailable", f"model unavailable: {value}", all_seed_ids, partial=True,
                    )
                if outcome == "accepted":
                    decision, validation, step_n = value
                    self._execute_action(case, decision, validation, step_n)
                    break
                rejected += 1
                retry_errors = tuple(value)
                if rejected >= 2:
                    self.repo.update_case(
                        case["id"], status="parked",
                        summary=json.dumps({
                            "model_conclusion": "deterministic_fallback_park",
                            "reasoning": "validation failed twice",
                            "validation_errors": list(retry_errors),
                        }, sort_keys=True),
                    )
                    break

