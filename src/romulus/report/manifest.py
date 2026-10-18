"""Build one immutable, versioned ReportManifest from a consistent DB snapshot (spec section 13)."""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from sqlalchemy import func, select

from romulus.decide.policy import LANE_ORDER
from romulus.store import schema as t
from romulus.store.db import digest, utcnow, write_txn
from romulus.store.repo import Repo, raw_id

MANIFEST_SCHEMA = "report-manifest@1"
REPORTABLE_LANES = ("urgent", "high", "lead")
CONCLUDED_CASE_STATUSES = {"closed", "parked", "escalated"}


def _jsonable(v):
    return json.loads(json.dumps(v, default=str))


def _citations(repo: Repo, cand: dict) -> list[dict]:
    """Resolve every cited event to retained raw records (or mark the citation broken)."""
    events = {e["id"]: e for e in repo.events_by_ids(cand["event_ids"])}
    cites = []
    for eid in cand["event_ids"]:
        ev = events.get(eid)
        if ev is None:
            cites.append({"event_id": eid, "status": "broken: typed event not retained"})
            continue
        rids = ev["raw_ids"]
        raws = {r["id"]: r for r in repo.raw_records(rids)}
        for ref in ev["event"]["raw"]:
            rid = raw_id(ref["target"], ref["native_id"])
            r = raws.get(rid)
            cites.append({"event_id": eid, "family": ev["family"], "event_ts": str(ev["ts"]), "host": ev["host"],
                          "target": ref["target"], "native_id": ref["native_id"], "digest": ref["digest"],
                          "status": "retained" if r and r["digest"] == ref["digest"] else
                                    "broken: raw copy missing" if not r else "broken: digest mismatch"})
    return cites


def _coverage(cells: list[dict]) -> dict:
    by_rule: dict[str, Counter] = defaultdict(Counter)
    evaluated: Counter = Counter()
    for c in cells:
        by_rule[c["rule_id"]][c["state"]] += 1
        evaluated[c["rule_id"]] += c["evaluated"] or 0
    rows = []
    for rule, states in sorted(by_rule.items()):
        partial = sum(n for s, n in states.items() if "partial" in s or "failed" in s)
        rows.append({"rule_id": rule, "states": dict(states), "records_evaluated": evaluated[rule],
                     "negative_claim": "none (rule matched)" if any(s.startswith("match") for s in states) else
                                       "complete" if partial == 0 and states.get("no_match_complete") else
                                       "unresolved: partial or unevaluated partitions" if partial else
                                       "not applicable to the data in scope"})
    return {"rules": rows}


def _case_conclusion(summary: str | None) -> dict | None:
    if not summary:
        return None
    try:
        parsed = json.loads(summary)
    except (json.JSONDecodeError, TypeError):
        return {"model_conclusion": "legacy_summary", "reasoning": str(summary), "evidence_ids": []}
    return parsed if isinstance(parsed, dict) else {"model_conclusion": "legacy_summary", "reasoning": str(parsed)}


def _investigations(repo: Repo, hunt_id: str, candidates: list[dict], agent: dict) -> dict:
    cases = repo.cases(hunt_id)
    seed_candidates = {
        candidate["id"]: candidate
        for candidate in candidates
        if candidate["lane"] != "context" and candidate.get("source_case_id") is None
    }
    contributed = defaultdict(list)
    for candidate in candidates:
        if candidate.get("source_case_id"):
            contributed[candidate["source_case_id"]].append(candidate["id"])

    categorized: set[str] = set()
    concluded: list[str] = []
    unfinished: list[str] = []
    case_rows = []
    pivot_proposals = 0
    executed_pivots = 0
    for case in cases:
        steps = repo.case_steps(case["id"])
        seed_ids: list[str] = []
        for step in steps:
            decision = step.get("decision") or {}
            if step["n"] == 0 and decision.get("action") == "seed":
                seed_ids = [seed_id for seed_id in decision.get("seed_candidate_ids") or []
                            if seed_id in seed_candidates]
                break
        unique_seed_ids = [seed_id for seed_id in seed_ids if seed_id not in categorized]
        categorized.update(unique_seed_ids)
        if case["status"] in CONCLUDED_CASE_STATUSES:
            concluded.extend(unique_seed_ids)
        else:
            unfinished.extend(unique_seed_ids)
        pivot_steps = []
        for step in steps:
            decision = step.get("decision") or {}
            if decision.get("action") != "pivot":
                continue
            pivot_proposals += 1
            if step["accepted"] and step.get("result_digest") is not None:
                executed_pivots += 1
            pivot_steps.append({
                "n": step["n"], "tool": decision.get("tool"), "hypothesis": decision.get("hypothesis"),
                "evidence_ids": decision.get("evidence_ids") or [], "arguments": decision.get("arguments") or {},
                "accepted": bool(step["accepted"]), "rejection": step.get("rejection"),
                "task_id": step.get("task_id"), "result": step.get("result_digest"),
            })
        calls = repo.model_calls(case_id=case["id"])
        case_rows.append({
            "id": case["id"], "title": case["title"], "status": case["status"],
            "priority": case["priority"], "seed_candidate_ids": seed_ids,
            "entities": case["entities"], "hypotheses": case["hypotheses"],
            "steps_used": case["steps_used"], "step_budget": case["step_budget"],
            "pivot_steps": pivot_steps,
            "conclusion": _case_conclusion(case.get("summary")),
            "contributed_candidate_ids": sorted(contributed.get(case["id"], [])),
            "model_calls": [{
                "id": call["id"], "purpose": call["purpose"], "model": call["model"],
                "status": call["status"], "duration_ms": call["duration_ms"],
                "validation": call["validation"],
            } for call in calls],
        })

    unassigned = sorted(set(seed_candidates) - categorized)
    unfinished = sorted(unfinished)
    concluded = sorted(concluded)
    unworked = sorted(set(unfinished) | set(unassigned))
    total_calls = sum(len(case["model_calls"]) for case in case_rows)
    discovered_ids = sorted(candidate["id"] for candidate in candidates if candidate.get("source_case_id"))
    return {
        "summary": {
            "status": agent.get("status", "unknown"),
            "cases": len(case_rows), "model_calls": total_calls, "pivots": executed_pivots,
            "pivot_proposals": pivot_proposals,
            "contributed_candidates": len(discovered_ids), "unworked_count": len(unworked),
        },
        "model_contribution": {
            "model_calls": total_calls, "pivot_steps": executed_pivots,
            "pivot_proposals": pivot_proposals,
            "candidate_ids": discovered_ids,
        },
        "seed_partition": {
            "concluded": concluded,
            "assigned_unfinished": unfinished,
            "unassigned": unassigned,
        },
        "unworked_seed_ids": unworked,
        "incomplete_case_ids": sorted(
            case["id"] for case in case_rows if case["status"] not in CONCLUDED_CASE_STATUSES
        ),
        "cases": case_rows,
    }


def build_manifest(repo: Repo, hunt_id: str, actor: str) -> dict:
    h = repo.get_hunt(hunt_id)
    if h is None:
        raise KeyError(hunt_id)
    cands = repo.candidates(hunt_id)
    cands.sort(key=lambda c: (LANE_ORDER.get(c["lane"], 9), -c["priority"], str(c["ts"])))
    findings = []
    for c in cands:
        if c["lane"] not in REPORTABLE_LANES:
            continue
        disp = repo.dispositions(c["id"])
        gates = dict(c["gate_results"])
        notes = gates.pop("_notes", [])
        findings.append({
            "id": c["id"], "lane": c["lane"], "severity": c["severity"], "confidence": c["confidence"],
            "priority": c["priority"], "priority_reasons": c["priority_reasons"], "rule_id": c["rule_id"],
            "rule_version": c["rule_version"], "claim": c["claim"], "claim_type": c["claim_type"],
            "observed_at": str(c["ts"]), "entities": c["entities"], "predicate_fields": c["predicate_fields"],
            "gates": gates, "notes": notes, "benign_alternatives": c["benign_alternatives"],
            "next_checks": c["next_checks"], "citations": _citations(repo, c),
            "source_case_id": c.get("source_case_id"),
            "analyst_status": disp[-1]["status"] if disp else "new",
            "disposition_history": [{"actor": d["actor"], "at": str(d["at"]), "status": d["status"],
                                     "note": d["note"]} for d in disp],
        })
    lane_counts = Counter(c["lane"] for c in cands)
    with repo.engine.connect() as conn:
        tasks = conn.execute(select(t.task.c.state, func.count()).where(t.task.c.hunt_id == hunt_id)
                             .group_by(t.task.c.state)).all()
        agent = conn.execute(select(t.audit_event.c.detail).where(t.audit_event.c.hunt_id == hunt_id,
                                                                  t.audit_event.c.action == "hunt.agent_summary")
                             .order_by(t.audit_event.c.id.desc())).scalar()
    broken = sum(1 for f in findings for c in f["citations"] if c["status"].startswith("broken"))
    hm = h["manifest"]
    m = {
        "schema": MANIFEST_SCHEMA,
        "hunt": {"id": hunt_id, "style": hm["style"], "hypothesis": hm.get("hypothesis", ""),
                 "window": hm["window"], "original_input": hm["original_input"], "targets": hm["targets"],
                 "manifest_digest": h["manifest_digest"], "created_by": h["created_by"],
                 "started_at": str(h["started_at"]), "ended_at": str(h["ended_at"])},
        "execution_state": h["execution_state"],
        "detection_result": h["detection_result"],
        "stop_reason": h["stop_reason"],
        "lane_counts": dict(lane_counts),
        "findings": findings,
        "context_items": lane_counts.get("context", 0),
        "coverage": _coverage(repo.rule_cells(hunt_id)),
        "tasks": {s: n for s, n in tasks},
        "agent": agent or {"status": "unknown"},
        "investigations": _investigations(repo, hunt_id, cands, agent or {"status": "unknown"}),
        "versions": {"pack": hm["pack"]["version"], "normalizer": hm["normalizer"], "policy": hm["policy"],
                     "model": hm["model"], "romulus": hm["romulus_version"]},
        "integrity": {"broken_citations": broken, "finalizable": broken == 0},
        "generated_by": actor,
    }
    return _jsonable(m)


def publish_revision(repo: Repo, hunt_id: str, actor: str) -> dict:
    """Append a new immutable revision; never edits an earlier one."""
    m = build_manifest(repo, hunt_id, actor)
    body_digest = digest({k: v for k, v in m.items() if k != "generated_by"})
    with write_txn(repo.engine) as conn:
        prev = conn.execute(select(t.report_manifest.c.id, t.report_manifest.c.revision, t.report_manifest.c.digest)
                            .where(t.report_manifest.c.hunt_id == hunt_id)
                            .order_by(t.report_manifest.c.revision.desc())).first()
        rev = (prev.revision + 1) if prev else 1
        m["revision"] = {"number": rev, "supersedes": prev.id if prev else None,
                         "unchanged_from_previous": bool(prev and prev.digest == body_digest)}
        rid = f"{hunt_id}-r{rev}"
        m["revision"]["id"] = rid
        conn.execute(t.report_manifest.insert().values(id=rid, hunt_id=hunt_id, revision=rev,
                                                       supersedes=prev.id if prev else None, manifest=m,
                                                       digest=body_digest, created_at=utcnow()))
    return m
