"""Explicit, bounded, resumable model-investigation controller."""
from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from time import monotonic
from typing import Any

from pydantic import ValidationError

from romulus.agent.brief import build_brief
from romulus.agent.cases import (
    MAX_SEEDS_PER_CASE,
    cluster_seed_candidates,
    seed_candidate_ids,
    seed_partition_families,
)
from romulus.agent.constraints import SCHEMA_FORM, eligible_evidence_aliases
from romulus.agent.models import AgentDecision, EntityRef, PivotResult
from romulus.agent.ollama import ModelResult, ModelUnavailable, OllamaClient
from romulus.agent.resolver import Resolution, resolve_output
from romulus.agent.tools import parse_tool_request, tool_catalog
from romulus.agent.validate import ValidationResult
from romulus.config import Settings
from romulus.store.db import digest, utcnow
from romulus.store.repo import Repo

_CONCLUDED = {"closed", "parked", "escalated"}
_UNFINISHED = {"open", "budget_exhausted", "fallback_parked"}


class Investigator:
    def __init__(self, settings: Settings, repo: Repo, pivot_executor: Any, hunt_id: str,
                 window: Any, model_client: Any | None = None,
                 heartbeat: Callable[[], None] | None = None,
                 owner_token: str | None = None,
                 clock: Callable[[], float] | None = None,
                 agent_mode: str | None = None):
        self.settings = settings
        self.repo = repo
        self.pivot_executor = pivot_executor
        self.hunt_id = hunt_id
        self.window = window
        self.model = model_client or OllamaClient(settings)
        self.heartbeat = heartbeat or (lambda: None)
        self.owner_token = owner_token
        self.clock = clock or monotonic
        self.mode = agent_mode or settings.agent_mode
        if self.mode not in {"model", "deterministic", "off"}:
            raise ValueError(f"invalid agent mode: {self.mode}")
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
        return seed_candidate_ids(steps)

    def _seed_cases(self) -> list[str]:
        candidates = [
            candidate for candidate in self.repo.candidates(self.hunt_id)
            if candidate["lane"] != "context" and candidate.get("source_case_id") is None
        ]
        candidates_by_id = {candidate["id"]: candidate for candidate in candidates}
        for case in self.repo.cases(self.hunt_id, statuses=["open"]):
            steps = self.repo.case_steps(case["id"])
            seed_ids = self._seed_ids(steps)
            if len(seed_ids) <= MAX_SEEDS_PER_CASE:
                continue
            retained_ids = seed_ids[:MAX_SEEDS_PER_CASE]
            retained_candidates = [
                candidates_by_id[seed_id] for seed_id in retained_ids if seed_id in candidates_by_id
            ]
            retained_entities: list[EntityRef] = []
            retained_priority = float(case["priority"])
            if retained_candidates:
                retained_priority = max(float(candidate["priority"]) for candidate in retained_candidates)
                retained_entities.extend(
                    entity
                    for cluster in cluster_seed_candidates(retained_candidates)
                    for entity in cluster.entities
                )
            else:
                for raw in case.get("entities") or []:
                    if isinstance(raw, (list, tuple)) and len(raw) >= 3:
                        retained_entities.append(EntityRef(kind=raw[0], value=str(raw[1]), role=str(raw[2])))
                    else:
                        retained_entities.append(EntityRef.model_validate(raw))
            for step in steps:
                decision = step.get("decision") or {}
                result = step.get("result_digest") or {}
                if not step.get("accepted") or decision.get("action") != "pivot":
                    continue
                for raw in result.get("entities") or []:
                    retained_entities.append(EntityRef.model_validate(raw))
            unique_entities = {
                (entity.kind, entity.value, entity.role): entity for entity in retained_entities
            }
            self.repo.repartition_case(
                case["id"], max(step["n"] for step in steps) + 1,
                {
                    "action": "seed_partition",
                    "seed_candidate_ids": retained_ids,
                    "previous_seed_count": len(seed_ids),
                },
                priority=retained_priority,
                entities=[entity.model_dump(mode="json") for entity in unique_entities.values()],
                owner_token=self.owner_token,
            )

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
            }, owner_token=self.owner_token)
            if created:
                self.repo.append_case_step(
                    cluster.id, 0,
                    {"action": "seed", "seed_candidate_ids": cluster.seed_candidate_ids},
                    True,
                    owner_token=self.owner_token,
                )
                assigned.update(cluster.seed_candidate_ids)
        return all_seed_ids

    def _next_step_number(self, case_id: str) -> int:
        steps = self.repo.case_steps(case_id)
        return max((step["n"] for step in steps), default=0) + 1

    def _executed_duplicate(self, case_id: str, request: Any) -> dict | None:
        def semantic_key(item: Any) -> tuple:
            args = item.arguments
            window = (args.start.astimezone(UTC), args.end.astimezone(UTC))
            entity = getattr(args, "entity", None)
            if entity is not None:
                return item.tool, window, entity.kind, entity.value
            return item.tool, window, args.host, args.process_id

        requested_key = semantic_key(request)
        candidates = self.repo.candidates(self.hunt_id)
        current_family = seed_partition_families(
            case_id, self.repo.case_steps(case_id), candidates,
        )
        for case in self.repo.cases(self.hunt_id):
            case_steps = self.repo.case_steps(case["id"])
            if seed_partition_families(case["id"], case_steps, candidates) != current_family:
                continue
            for step in case_steps:
                decision_data = step.get("decision") or {}
                if (not step.get("accepted") or step.get("result_digest") is None
                        or decision_data.get("action") != "pivot"):
                    continue
                try:
                    prior_request = parse_tool_request(AgentDecision.model_validate(decision_data))
                except (ValidationError, ValueError):
                    continue
                if semantic_key(prior_request) == requested_key:
                    return step
        return None

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
                "schema_form": SCHEMA_FORM,
            },
            "prompt_digest": digest({"system": brief.system, "user": brief.user, "schema": brief.schema}),
            "prompt_tokens_est": result.prompt_tokens_est,
            "prompt_eval_count": result.prompt_eval_count,
            "eval_count": result.eval_count,
            "duration_ms": result.duration_ms,
            "raw_response": result.raw,
            "parsed": result.parsed,
            "validation": validation_data,
            "status": status or result.status,
            "at": utcnow(),
        }, owner_token=self.owner_token)
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
            rejection=error, model_call_id=call_id, owner_token=self.owner_token,
        )
        self.repo.update_case(
            case["id"], owner_token=self.owner_token,
            steps_used=int(case["steps_used"]) + 1,
        )

    @staticmethod
    def _menu_snapshot(brief) -> list[dict]:
        return [option.model_dump(mode="json") for option in brief.menu.options]

    def _annotate_decision(
        self,
        decision: AgentDecision,
        brief,
        option_id: str,
        *,
        deterministic_fallback: bool = False,
        fallback_note: str = "",
        truncated_fields: list[str] | None = None,
        model_attempt: int | None = None,
    ) -> AgentDecision:
        option = next(item for item in brief.menu.options if item.id == option_id)
        return decision.model_copy(update={
            "chosen_option": option_id,
            "option_description": option.description,
            "menu": self._menu_snapshot(brief),
            "menu_hidden_count": brief.menu.hidden_count,
            "aliases": brief.aliases,
            "agent_mode": "deterministic" if self.mode == "deterministic" else "model",
            "deterministic_fallback": deterministic_fallback,
            "fallback_note": fallback_note,
            "text_truncated": list(truncated_fields or []),
            "model_attempt": model_attempt,
        })

    def _constraint_defect_decision(self, brief, result: ModelResult, attempt: int) -> dict:
        parsed = result.parsed if isinstance(result.parsed, dict) else {}
        return {
            "action": "constraint_defect",
            "model_output": result.parsed,
            "chosen_option": parsed.get("option"),
            "menu": self._menu_snapshot(brief),
            "menu_hidden_count": brief.menu.hidden_count,
            "aliases": brief.aliases,
            "agent_mode": "model",
            "deterministic_fallback": False,
            "fallback_note": "",
            "text_truncated": [],
            "model_attempt": attempt,
        }

    def _append_accepted(
        self,
        case: dict,
        decision: AgentDecision,
        step_n: int,
    ) -> None:
        stored = decision.model_dump(mode="json")
        pending_id = None
        if decision.action == "pivot":
            pending_id = "pending-" + digest({
                "case": case["id"], "step": step_n, "decision": stored,
            })[:20]
        self.repo.append_case_step(
            case["id"], step_n, stored, True, task_id=pending_id,
            owner_token=self.owner_token,
        )
        self.repo.update_case(
            case["id"], owner_token=self.owner_token,
            steps_used=int(case["steps_used"]) + 1,
        )

    def _call_once(self, case: dict, retry_errors: tuple[str, ...], attempt: int) -> tuple[str, Any]:
        step_n = self._next_step_number(case["id"])
        brief = build_brief(
            self.repo, case["id"], tool_catalog(), self.settings.ollama_num_ctx,
            retry_errors=retry_errors,
        )
        self.heartbeat()
        try:
            result = self.model.chat_json(
                self.settings.ollama_model_triage, brief.system, brief.user,
                brief.schema, max_out=900,
            )
        except ModelUnavailable as exc:
            self.heartbeat()
            self._record_exception(case, step_n, brief, str(exc))
            return "unavailable", str(exc)

        self.heartbeat()

        if not result.ok and result.status in {"truncated", "too_large", "error"}:
            call_id = self._record_call(case, step_n, brief, result, None)
            self.repo.append_case_step(
                case["id"], step_n, {"action": "model_error", "status": result.status}, False,
                rejection=result.error, model_call_id=call_id, owner_token=self.owner_token,
            )
            self.repo.update_case(
                case["id"], owner_token=self.owner_token,
                steps_used=int(case["steps_used"]) + 1,
            )
            return "unavailable", result.error or result.status

        resolution = resolve_output(
            result.parsed, brief, self.window,
            duplicate_check=lambda request: self._executed_duplicate(case["id"], request),
        )
        accepted = resolution.ok
        validation = resolution.validation or ValidationResult(False, list(resolution.errors))
        result_status = result.status if accepted else "constraint_defect"
        call_id = self._record_call(case, step_n, brief, result, validation, status=result_status)
        decision = None
        if accepted and resolution.decision is not None:
            option_id = str(result.parsed["option"])
            decision = self._annotate_decision(
                resolution.decision, brief, option_id,
                truncated_fields=resolution.truncated_fields, model_attempt=attempt,
            )
            stored_decision = decision.model_dump(mode="json")
        else:
            stored_decision = self._constraint_defect_decision(brief, result, attempt)
        pending_id = None
        if accepted and decision is not None and decision.action == "pivot":
            pending_id = "pending-" + digest({
                "case": case["id"], "step": step_n, "decision": stored_decision,
            })[:20]
        self.repo.append_case_step(
            case["id"], step_n, stored_decision, accepted,
            rejection="; ".join(resolution.errors) if resolution.errors else None,
            model_call_id=call_id, task_id=pending_id, owner_token=self.owner_token,
        )
        self.repo.update_case(
            case["id"], owner_token=self.owner_token,
            steps_used=int(case["steps_used"]) + 1,
        )
        self.heartbeat()
        if not accepted:
            return "rejected", resolution.errors
        return "accepted", (decision, validation, step_n)

    def _deterministic_resolution(self, case: dict, brief, option) -> Resolution:
        aliases = eligible_evidence_aliases(
            option, brief.aliases, brief.known_candidates, brief.injection_evidence_ids,
        )
        if not aliases:
            return Resolution(
                errors=[f"no eligible evidence card for deterministic option {option.id}"],
                constraint_defect=True,
            )
        return resolve_output({
            "option": option.id,
            "evidence": [aliases[0]],
            "rationale": f"Deterministically selected the highest-ranked legal option {option.id}.",
        }, brief, self.window,
            duplicate_check=lambda request: self._executed_duplicate(case["id"], request))

    def _take_deterministic_action(
        self,
        case: dict,
        *,
        fallback: bool = False,
        retry_errors: tuple[str, ...] = (),
    ) -> bool:
        brief = build_brief(
            self.repo, case["id"], tool_catalog(), self.settings.ollama_num_ctx,
            retry_errors=retry_errors,
        )
        option = brief.menu.pivot_options[0] if brief.menu.pivot_options else next(
            (item for item in brief.menu.options if item.decision.action == "park_as_lead"),
            None,
        )
        if option is None:
            return False
        resolution = self._deterministic_resolution(case, brief, option)
        if not resolution.ok or resolution.decision is None or resolution.validation is None:
            return False
        note = "model output failed twice; selected top-ranked pivot"
        if option.decision.action == "park_as_lead":
            note = "model output failed twice; no pivot option remained, so the case was parked"
        resolved_decision = resolution.decision
        if not fallback and resolved_decision.action == "park_as_lead":
            resolved_decision = resolved_decision.model_copy(update={
                "reasoning": "deterministic investigation complete",
                "resolution_needed": "deterministic investigation complete",
            })
        decision = self._annotate_decision(
            resolved_decision, brief, option.id,
            deterministic_fallback=fallback, fallback_note=note if fallback else "",
            truncated_fields=resolution.truncated_fields,
        )
        step_n = self._next_step_number(case["id"])
        self._append_accepted(case, decision, step_n)
        if fallback and decision.action == "park_as_lead":
            self.repo.update_case(
                case["id"], owner_token=self.owner_token, status="fallback_parked",
                summary=json.dumps({
                    "model_conclusion": "deterministic_fallback_park",
                    "reasoning": note,
                    "validation_errors": list(retry_errors),
                    "analyst_flag": {
                        "reason": "validation_fallback",
                        "message": "Model output failed validation twice and no pivot remained; analyst review is required.",
                    },
                }, sort_keys=True),
            )
        else:
            self._execute_action(case, decision, resolution.validation, step_n)
        return True

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

    def _anchor_time(self, decision: AgentDecision, request: Any) -> datetime | None:
        """Use the first cited event inside the requested window as the pivot's sampling anchor."""
        rows = {row["id"]: row for row in self.repo.events_by_ids(decision.evidence_ids)}
        start = request.arguments.start.astimezone(UTC)
        end = request.arguments.end.astimezone(UTC)
        for event_id in decision.evidence_ids:
            row = rows.get(event_id)
            if row is None:
                continue
            value = row.get("ts")
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value)
                except ValueError:
                    continue
            if not isinstance(value, datetime):
                continue
            value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
            if start <= value < end:
                return value
        return None

    def _execute_action(self, case: dict, decision: AgentDecision,
                        validation: ValidationResult, step_n: int) -> None:
        if decision.action == "pivot":
            result: PivotResult = self.pivot_executor.run(
                case["id"], validation.request,
                anchor_ts=self._anchor_time(decision, validation.request),
            )
            self.partial_pivot |= result.status in {"partial", "failed"}
            self.repo.update_case_step(
                case["id"], step_n,
                task_id=result.task_ids[0] if result.task_ids else None,
                result_digest=result.model_dump(mode="json"),
                owner_token=self.owner_token,
            )
            hypotheses = list(case.get("hypotheses") or [])
            if decision.hypothesis and decision.hypothesis not in hypotheses:
                hypotheses.append(decision.hypothesis)
            self.repo.update_case(
                case["id"], owner_token=self.owner_token, hypotheses=hypotheses,
                entities=self._merge_entities(case, result.entities),
            )
        elif decision.action == "escalate":
            self.repo.update_case(
                case["id"], owner_token=self.owner_token,
                status="escalated", summary=self._conclusion(decision),
            )
        elif decision.action == "close":
            self.repo.update_case(
                case["id"], owner_token=self.owner_token,
                status="closed", summary=self._conclusion(decision),
            )
        elif decision.action == "park_as_lead":
            self.repo.update_case(
                case["id"], owner_token=self.owner_token,
                status="parked", summary=self._conclusion(decision),
            )
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
                }, owner_token=self.owner_token)
                if created:
                    self.repo.append_case_step(
                        child_id, 0,
                        {"action": "spawn_seed", "parent_case_id": case["id"],
                         "evidence_ids": decision.evidence_ids},
                        True,
                        owner_token=self.owner_token,
                    )

    def _replay_pending(self) -> None:
        for step in self.repo.pending_case_steps(self.hunt_id):
            decision = AgentDecision.model_validate(step["decision"])
            request = parse_tool_request(decision)
            result: PivotResult = self.pivot_executor.run(
                step["case_id"], request,
                anchor_ts=self._anchor_time(decision, request),
            )
            self.partial_pivot |= result.status in {"partial", "failed"}
            self.repo.update_case_step(
                step["case_id"], step["n"],
                task_id=result.task_ids[0] if result.task_ids else step["task_id"],
                result_digest=result.model_dump(mode="json"),
                owner_token=self.owner_token,
            )
            case = self.repo.case(step["case_id"])
            if case is not None:
                hypotheses = list(case.get("hypotheses") or [])
                if decision.hypothesis and decision.hypothesis not in hypotheses:
                    hypotheses.append(decision.hypothesis)
                self.repo.update_case(
                    case["id"], owner_token=self.owner_token, hypotheses=hypotheses,
                    entities=self._merge_entities(case, result.entities),
                )
            self.heartbeat()

    def _mark_budget_exhausted(self) -> None:
        for case in self.repo.cases(self.hunt_id, statuses=["open"]):
            self.repo.update_case(
                case["id"], owner_token=self.owner_token, status="budget_exhausted",
            )

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
        analyst_flags = []
        for case in cases:
            if case["status"] != "fallback_parked":
                continue
            try:
                case_summary = json.loads(case.get("summary") or "{}")
            except (json.JSONDecodeError, TypeError):
                case_summary = {}
            flag = case_summary.get("analyst_flag") or {
                "reason": "validation_fallback",
                "message": "Repeated invalid model output requires analyst review.",
            }
            analyst_flags.append({"case_id": case["id"], **flag})
        calls = self.repo.model_calls(hunt_id=self.hunt_id)
        pivot_steps = [
            step for case in cases for step in self.repo.case_steps(case["id"])
            if (step.get("decision") or {}).get("action") == "pivot" and step.get("accepted")
        ]
        partial_pivot_steps = [
            step for step in pivot_steps
            if (step.get("result_digest") or {}).get("status") in {"partial", "failed"}
        ]
        duplicate_pivots = [
            step for case in cases for step in self.repo.case_steps(case["id"])
            if (step.get("decision") or {}).get("action") == "pivot" and not step.get("accepted")
            and "duplicate pivot:" in (step.get("rejection") or "")
        ]
        decisions = [
            step.get("decision") or {}
            for case in cases for step in self.repo.case_steps(case["id"])
        ]
        return {
            "status": status,
            "mode": self.mode,
            "partial": partial or self.partial_pivot,
            "stop_reason": reason,
            "cases_total": len(cases),
            "seed_count": len(all_seed_ids),
            "concluded_seed_ids": sorted(concluded),
            "assigned_unfinished_seed_ids": sorted(unfinished),
            "unassigned_seed_ids": sorted(unassigned),
            "unworked_seed_ids": sorted(unworked),
            "unworked_count": len(unworked),
            "fallback_parked_count": len(analyst_flags),
            "analyst_flags": analyst_flags,
            "model_calls": len(calls),
            "constraint_defects": sum(call.get("status") == "constraint_defect" for call in calls),
            "valid_first_attempt": sum(
                decision.get("model_attempt") == 1
                for decision in decisions
            ),
            "deterministic_fallbacks": sum(
                bool(decision.get("deterministic_fallback"))
                for decision in decisions
            ),
            "pivots": len(pivot_steps),
            "partial_pivots": len(partial_pivot_steps),
            "duplicate_pivots_blocked": len(duplicate_pivots),
        }

    def _completed_summary(self, all_seed_ids: list[str]) -> dict:
        if self.repo.cases(self.hunt_id, statuses=["fallback_parked"]):
            return self._summary(
                "completed",
                "all runnable cases ended; fallback-parked cases require analyst review",
                all_seed_ids,
            )
        return self._summary("completed", "all selected cases concluded", all_seed_ids)

    def run(self) -> dict:
        if self.mode == "off":
            seed_ids = [
                candidate["id"] for candidate in self.repo.candidates(self.hunt_id)
                if candidate["lane"] != "context" and candidate.get("source_case_id") is None
            ]
            return {
                "status": "disabled", "mode": "off", "partial": False,
                "stop_reason": "investigator disabled (agent mode off)",
                "seed_count": len(seed_ids), "unworked_seed_ids": sorted(seed_ids),
                "unworked_count": len(seed_ids), "model_calls": 0,
                "constraint_defects": 0, "valid_first_attempt": 0,
                "deterministic_fallbacks": 0,
            }
        all_seed_ids = self._seed_cases()
        self._replay_pending()
        if not self.repo.cases(self.hunt_id, statuses=["open"]):
            return self._completed_summary(all_seed_ids)

        while True:
            open_cases = self.repo.cases(self.hunt_id, statuses=["open"])
            if not open_cases:
                if self.repo.cases(self.hunt_id, statuses=["budget_exhausted"]):
                    return self._summary(
                        "budget_exhausted", "all open cases exhausted their step budgets", all_seed_ids,
                    )
                return self._completed_summary(all_seed_ids)
            if self._wall_exhausted():
                self._mark_budget_exhausted()
                return self._summary("budget_exhausted", "agent wall-clock budget exhausted", all_seed_ids)
            if self._total_steps() >= self.total_budget:
                self._mark_budget_exhausted()
                return self._summary("budget_exhausted", "agent total-step budget exhausted", all_seed_ids)

            for case in open_cases:
                if int(case["steps_used"]) >= min(int(case["step_budget"]), self.per_case_budget):
                    self.repo.update_case(
                        case["id"], owner_token=self.owner_token, status="budget_exhausted",
                    )
            open_cases = self.repo.cases(self.hunt_id, statuses=["open"])
            if not open_cases:
                return self._summary("budget_exhausted", "all open cases exhausted their step budgets", all_seed_ids)

            case = min(open_cases, key=lambda item: (int(item["steps_used"]), -float(item["priority"]), item["id"]))
            if self.mode == "deterministic":
                if not self._take_deterministic_action(case):
                    remaining = build_brief(
                        self.repo, case["id"], tool_catalog(), self.settings.ollama_num_ctx,
                    )
                    status = "budget_exhausted" if remaining.menu.pivot_options else "fallback_parked"
                    self.repo.update_case(
                        case["id"], owner_token=self.owner_token, status=status,
                        summary=json.dumps({
                            "model_conclusion": "deterministic_fallback_park",
                            "reasoning": "no legal deterministic option could be resolved",
                            "analyst_flag": {
                                "reason": "no_legal_deterministic_option",
                                "message": "No legal deterministic option remained; analyst review is required.",
                            },
                        }, sort_keys=True),
                    )
                continue
            retry_errors: tuple[str, ...] = ()
            rejected = 0
            while True:
                case = self.repo.case(case["id"])
                if case is None:
                    break
                if self._wall_exhausted() or self._total_steps() >= self.total_budget:
                    break
                per_case_limit = min(int(case["step_budget"]), self.per_case_budget)
                if int(case["steps_used"]) >= per_case_limit:
                    self.repo.update_case(
                        case["id"], owner_token=self.owner_token, status="budget_exhausted",
                    )
                    break
                outcome, value = self._call_once(case, retry_errors, rejected + 1)
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
                    case = self.repo.case(case["id"])
                    if case is not None:
                        per_case_limit = min(int(case["step_budget"]), self.per_case_budget)
                        budget_available = (
                            int(case["steps_used"]) < per_case_limit
                            and self._total_steps() < self.total_budget
                            and not self._wall_exhausted()
                        )
                        if not budget_available:
                            break
                        if self._take_deterministic_action(
                                case, fallback=True, retry_errors=retry_errors):
                            break
                        remaining = build_brief(
                            self.repo, case["id"], tool_catalog(), self.settings.ollama_num_ctx,
                            retry_errors=retry_errors,
                        )
                        if remaining.menu.pivot_options:
                            self.repo.update_case(
                                case["id"], owner_token=self.owner_token, status="budget_exhausted",
                                summary=json.dumps({
                                    "reasoning": "a pivot remained but no legal deterministic citation was available",
                                    "validation_errors": list(retry_errors),
                                }, sort_keys=True),
                            )
                            break
                    injection_related = any(
                        "untrusted instruction-like telemetry" in error
                        for error in retry_errors
                    )
                    analyst_flag = {
                        "reason": (
                            "untrusted_instruction_telemetry"
                            if injection_related else "validation_fallback"
                        ),
                        "message": (
                            "untrusted instruction-like telemetry contributed to rejected model output; "
                            "analyst review is required."
                            if injection_related else
                            "Model output failed validation twice; analyst review is required."
                        ),
                    }
                    self.repo.update_case(
                        case["id"], owner_token=self.owner_token, status="fallback_parked",
                        summary=json.dumps({
                            "model_conclusion": "deterministic_fallback_park",
                            "reasoning": (
                                "validation failed twice; no budget or legal deterministic option remained"
                            ),
                            "validation_errors": list(retry_errors),
                            "analyst_flag": analyst_flag,
                        }, sort_keys=True),
                    )
                    break

