"""Rebuild the investigator's historical briefs as frozen bakeoff tasks.

For every model call a hunt's investigator made, the case is rewound to the state it had just before that
step and ``build_brief`` (the production builder) is run again, once per requested ``num_ctx``. The rebuilt
brief at the production ``num_ctx`` is checked against the stored ``prompt_digest``, so a task either
reproduces exactly what the model saw (``digest_match``) or says it does not.

The live store is never opened for writing: it is copied with SQLite's backup API from a ``mode=ro``
connection, and the export reads the copy.
"""
from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from romulus.agent.brief import BuiltBrief, build_brief
from romulus.agent.cases import MAX_SEEDS_PER_CASE, cluster_seed_candidates, seed_candidate_ids
from romulus.agent.models import EntityRef
from romulus.agent.tools import tool_catalog
from romulus.store.db import digest, make_engine
from romulus.store.repo import Repo

TASK_SCHEMA = "bakeoff-task/1"
MAX_OUT = 900          # the controller's fixed output budget per call


@contextmanager
def readonly_repo(db_path: str | Path) -> Iterator[Repo]:
    """A Repo over a private snapshot of the store; the live database is only ever opened read-only."""
    source_uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    with tempfile.TemporaryDirectory(prefix="romulus-bakeoff-") as tmp:
        snapshot = Path(tmp) / "snapshot.db"
        src = sqlite3.connect(source_uri, uri=True)
        dst = sqlite3.connect(snapshot)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        engine = make_engine(snapshot)
        try:
            yield Repo(engine)
        finally:
            engine.dispose()


def _entity_key(entity: EntityRef) -> tuple[str, str, str]:
    return entity.kind, entity.value, entity.role


def _initial_entities(repo: Repo, hunt_id: str, case: dict, steps: list[dict]) -> list[EntityRef]:
    """Entities the case was created with, recomputed the way the controller created it."""
    first = (steps[0].get("decision") or {}) if steps and steps[0]["n"] == 0 else {}
    if first.get("action") == "seed":
        seeds = [
            candidate for candidate in repo.candidates(hunt_id)
            if candidate["lane"] != "context" and candidate.get("source_case_id") is None
        ]
        for cluster in cluster_seed_candidates(seeds):
            if cluster.id == case["id"]:
                return list(cluster.entities)
    if first.get("action") == "spawn_seed":
        for step in repo.case_steps(first.get("parent_case_id") or ""):
            decision = step.get("decision") or {}
            if not step.get("accepted") or decision.get("action") != "spawn" or not decision.get("entity"):
                continue
            entity = EntityRef.model_validate(decision["entity"])
            child = "case-" + digest({"parent": first["parent_case_id"],
                                      "entity": entity.model_dump(mode="json")})[:16]
            if child == case["id"]:
                return [entity]
    return [EntityRef.model_validate(raw) for raw in case.get("entities") or [] if isinstance(raw, dict)]


def _case_before(case: dict, prior_steps: list[dict], initial: list[EntityRef]) -> dict:
    """The case row as the controller held it before the next call: open, with pivots merged in order."""
    entities = {_entity_key(entity): entity for entity in initial}
    hypotheses: list[str] = []
    for step in prior_steps:
        decision = step.get("decision") or {}
        result = step.get("result_digest")
        if not step.get("accepted") or decision.get("action") != "pivot" or result is None:
            continue
        hypothesis = decision.get("hypothesis")
        if hypothesis and hypothesis not in hypotheses:
            hypotheses.append(hypothesis)
        for raw in result.get("entities") or []:
            entity = EntityRef.model_validate(raw)
            entities[_entity_key(entity)] = entity
    state = dict(case)
    state.update(
        status="open",
        steps_used=sum(1 for step in prior_steps if step["n"] >= 1),
        hypotheses=hypotheses,
        entities=[entity.model_dump(mode="json") for entity in entities.values()],
        summary=None,
    )
    return state


def _set_field(event: dict, field: str, value: Any) -> None:
    fields = event.setdefault("fields", {})
    current = fields.get(field)
    if isinstance(current, dict) and "value" in current:
        current["value"] = value
    else:
        fields[field] = value


class _StepView:
    """The read surface ``build_brief`` uses, rewound to just before one step."""

    def __init__(self, repo: Repo, case: dict, prior_steps: list[dict], before: Any,
                 mutations: list[dict] | None = None):
        self._repo = repo
        self._case = case
        self._steps = prior_steps
        self._before = before
        self._mutations = mutations or []

    def case(self, case_id: str) -> dict | None:
        return self._case if case_id == self._case["id"] else None

    def case_steps(self, case_id: str) -> list[dict]:
        return self._steps if case_id == self._case["id"] else []

    def get_hunt(self, hunt_id: str) -> dict | None:
        return self._repo.get_hunt(hunt_id)

    def cases(self, hunt_id: str) -> list[dict]:
        rows = [row for row in self._repo.cases(hunt_id) if row["created_at"] < self._before]
        return [self._case if row["id"] == self._case["id"] else row for row in rows]

    def candidates(self, hunt_id: str, lanes: list[str] | None = None) -> list[dict]:
        rows = self._repo.candidates(hunt_id, lanes)
        return [row for row in rows if row["created_at"] < self._before]

    def events_by_ids(self, ids: list[str]) -> list[dict]:
        rows = self._repo.events_by_ids(ids)
        if not self._mutations:
            return rows
        rows = copy.deepcopy(rows)
        by_id = {row["id"]: row for row in rows}
        for mutation in self._mutations:
            row = by_id.get(mutation["event_id"])
            if row is not None:
                _set_field(row.setdefault("event", {}), mutation["field"], mutation["value"])
        return rows


def _retry_errors(previous: dict | None, calls: dict[str, dict]) -> tuple[str, ...] | None:
    """Errors the controller fed back after a rejected first attempt, if the previous step was one."""
    if previous is None or previous.get("accepted") or not previous.get("model_call_id"):
        return None
    call = calls.get(previous["model_call_id"])
    if call is None or call.get("status") not in {"invalid", "constraint_defect"}:
        return None
    validation = call.get("validation")
    if validation and validation.get("errors"):
        return tuple(validation["errors"])
    return (previous["rejection"],) if previous.get("rejection") else None


def serialize_brief(brief: BuiltBrief) -> dict:
    return {
        "system": brief.system,
        "user": brief.user,
        "output_schema": brief.schema,
        "menu": brief.menu.model_dump(mode="json"),
        "aliases": brief.aliases,
        "token_estimate": brief.token_estimate,
        "shrink_actions": list(brief.shrink_actions),
        "known_candidates": {
            cid: {"claim": c.get("claim"), "lane": c.get("lane"), "event_ids": list(c.get("event_ids") or [])}
            for cid, c in sorted(brief.known_candidates.items())
        },
        "known_evidence_ids": sorted(brief.known_evidence_ids),
        "known_entities": [entity.model_dump(mode="json") for entity in brief.known_entities],
        "injection_flags": list(brief.injection_flags),
        "injection_evidence_ids": sorted(brief.injection_evidence_ids),
        "known_process_ids": sorted([host, pid] for host, pid in brief.known_process_ids),
    }


def _prior_for_duplicates(prior_steps: list[dict]) -> list[dict]:
    """Just enough of the prior steps for the controller's duplicate-pivot check."""
    return [{
        "n": step["n"], "decision": step.get("decision"), "accepted": bool(step.get("accepted")),
        "result_digest": None if step.get("result_digest") is None
        else {"status": (step["result_digest"] or {}).get("status")},
    } for step in prior_steps]


def _effective_prior_steps(prior_steps: list[dict]) -> list[dict]:
    """Bound pre-migration seed groups for replay without rewriting or claiming an exact digest."""
    active_seed_ids = seed_candidate_ids(prior_steps)
    if len(active_seed_ids) <= MAX_SEEDS_PER_CASE:
        return prior_steps
    effective = copy.deepcopy(prior_steps)
    for step in effective:
        decision = step.get("decision") or {}
        if step.get("n") == 0 and decision.get("action") == "seed":
            decision["effective_seed_candidate_ids"] = active_seed_ids[:MAX_SEEDS_PER_CASE]
            break
    return effective


def export_tasks(repo: Repo, hunt_id: str, num_ctx_values: list[int],
                 variants: list[dict] | None = None) -> tuple[list[dict], dict]:
    """Return (tasks, stats). ``variants`` are {variant, task_id, mutations[]} applied to a base step."""
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    window = hunt["manifest"]["window"]
    by_base: dict[str, list[dict]] = {}
    for variant in variants or []:
        by_base.setdefault(variant["task_id"], []).append(variant)

    tasks: list[dict] = []
    stats = {"model_calls": 0, "tasks": 0, "digest_match": 0, "digest_mismatch": 0, "variants": 0,
             "unfit_briefs": 0}
    catalog = tool_catalog()
    for case in repo.cases(hunt_id):
        steps = repo.case_steps(case["id"])
        calls = {call["id"]: call for call in repo.model_calls(hunt_id=hunt_id, case_id=case["id"])}
        initial = _initial_entities(repo, hunt_id, case, steps)
        by_n = {step["n"]: step for step in steps}
        for step in steps:
            call = calls.get(step.get("model_call_id") or "")
            if step["n"] < 1 or call is None:
                continue
            stats["model_calls"] += 1
            prior = [s for s in steps if s["n"] < step["n"]]
            state = _case_before(case, prior, initial)
            effective_prior = _effective_prior_steps(prior)
            view = _StepView(repo, state, effective_prior, call["at"])
            options = call.get("options") or {}
            production_ctx = int(options.get("num_ctx") or num_ctx_values[0])

            retry = _retry_errors(by_n.get(step["n"] - 1), calls)
            chosen: tuple[str, ...] = ()
            matched = False
            for attempt_errors in ([retry] if retry else []) + [()]:
                try:
                    brief = build_brief(view, case["id"], catalog, production_ctx, max_out=MAX_OUT,
                                        retry_errors=attempt_errors)
                except ValueError:
                    continue
                if digest({"system": brief.system, "user": brief.user,
                           "schema": brief.schema}) == call["prompt_digest"]:
                    chosen, matched = attempt_errors, True
                    break
            if not matched and retry:
                chosen = retry
            stats["digest_match" if matched else "digest_mismatch"] += 1

            task_id = f"{hunt_id}/{case['id']}/{step['n']}"
            base = {
                "schema": TASK_SCHEMA,
                "task_id": task_id,
                "variant": None,
                "origin": {
                    "hunt_id": hunt_id, "case_id": case["id"], "step": step["n"],
                    "model_call_id": call["id"],
                    "production": {
                        "model": call.get("model"), "num_ctx": production_ctx,
                        "think": options.get("think"), "status": call.get("status"),
                        "accepted": bool(step.get("accepted")), "prompt_digest": call["prompt_digest"],
                        "digest_match": matched,
                    },
                },
                "attempt": 2 if chosen else 1,
                "retry_errors": list(chosen),
                "window": {"start": window["start"], "end": window["end"]},
                "prior_steps": _prior_for_duplicates(prior),
            }
            specs = [(None, [], view)] + [
                (variant["variant"], variant["mutations"],
                 _StepView(repo, state, effective_prior, call["at"], variant["mutations"]))
                for variant in by_base.get(task_id, [])
            ]
            for name, mutations, step_view in specs:
                task = dict(base, briefs={})
                if name is not None:
                    task.update(task_id=f"{task_id}+{name}", variant={"name": name, "mutations": mutations})
                    stats["variants"] += 1
                for num_ctx in num_ctx_values:
                    try:
                        brief = build_brief(step_view, case["id"], catalog, num_ctx, max_out=MAX_OUT,
                                            retry_errors=chosen)
                    except ValueError as exc:
                        task["briefs"][str(num_ctx)] = {"error": str(exc)}
                        stats["unfit_briefs"] += 1
                        continue
                    task["briefs"][str(num_ctx)] = serialize_brief(brief)
                tasks.append(task)
                stats["tasks"] += 1
    return tasks, stats


def write_jsonl(path: str | Path, rows: list[dict]) -> None:
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(json.dumps(row, sort_keys=True, default=str) + "\n" for row in rows)


def read_jsonl(path: str | Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
