"""Build one immutable, versioned ReportManifest from a consistent DB snapshot (spec section 13)."""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from sqlalchemy import func, select

from romulus.decide.policy import LANE_ORDER
from romulus.detect.registry import ALL_PLAYBOOKS
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


UNRESOLVED_STATES = (
    "planned", "executed_failed", "evaluated_partial", "match_on_partial", "positive_only_partial",
)
_NO_ASSURANCE = ("no rule in this pack can prove absence for this behavior yet; negatives from kernel file and "
                 "path records are planned (M3)")


def _po(what: str) -> str:
    return f"not assessable by design: positive-only rule ({what}; {_NO_ASSURANCE})"


POSITIVE_ONLY_CLAIMS = {
    "host.download_piped_to_shell": _po("script text can show download-to-interpreter intent but cannot prove it ran"),
    "host.ssh_authorized_keys_write": _po("script text or command arguments can show an authorized_keys write but "
                                          "cannot prove that none happened; shell-builtin redirects create no process"),
    "host.script_from_temp_dir": _po("interpreter argv can show a temp-directory script operand but cannot prove "
                                     "that no script ran from a temp directory"),
    "host.exec_from_temp_dir": _po("the kernel-recorded executable is the interpreter for #! scripts, so it cannot "
                                   "prove that no temp-directory program ran"),
    "host.web_service_spawns_interpreter": _po("the interpreter is identified from argv[0], which a renamed or "
                                               "copied interpreter or exec -a can change"),
    "host.downloader_feeds_interpreter": _po("downloader, interpreter and stdin use are identified from argv"),
    "host.python_pty_spawn": _po("python and its -c code are identified from argv; script files, stdin and "
                                 "wrapped code are not seen"),
    "host.firewall_rule_change_command": _po("the firewall tool and change flags are identified from argv"),
    "host.credential_store_read": _po("the reader and the file are identified from argv, not from a file-access "
                                      "record"),
    "net.tool_user_agent_http": (
        "not assessable by design: positive-only rule (the user agent is self-reported, attacker-controlled text, "
        "and only agents beginning with a listed tool name are matched; its absence proves nothing)"
    ),
    "host.ssh_login_external_source": _po("logins are identified by parsing sshd log message text; unrecognized "
                                          "formats are not seen"),
}


POSITIVE_ONLY_RULE_IDS = frozenset({cls.id for cls in ALL_PLAYBOOKS if not cls.assures_negative}
                                   | set(POSITIVE_ONLY_CLAIMS))


def _coverage(cells: list[dict], targets: list[str] | None = None, rule_ids: list[str] | None = None,
              sweep_finished: bool = True) -> dict:
    """Per-rule negative claim. 'complete' requires: the sweep finished, every manifest target has
    cells for the rule, no cell is planned/failed/partial, and at least one complete no-match.
    Anything less is 'unresolved' with the reason; absence of data is 'not applicable', never a
    negative."""
    cells = [c for c in cells if c["state"] != "split"]          # superseded by their children
    by_rule: dict[str, Counter] = defaultdict(Counter)
    evaluated: Counter = Counter()
    rule_targets: dict[str, set] = defaultdict(set)
    for c in cells:
        by_rule[c["rule_id"]][c["state"]] += 1
        if c["target"] != "*":
            evaluated[c["rule_id"]] += c["evaluated"] or 0
            rule_targets[c["rule_id"]].add(c["target"])
    for rid in rule_ids or []:
        by_rule.setdefault(rid, Counter())
    rows = []
    for rule, states in sorted(by_rule.items()):
        reasons = []
        if not sweep_finished:
            reasons.append("sweep did not finish")
        missing = sorted(set(targets or []) - rule_targets[rule])
        if missing:
            reasons.append(f"no evaluation recorded for target(s) {missing}")
        bad = {s: n for s, n in states.items() if s in UNRESOLVED_STATES}
        if bad:
            reasons.append("partial, failed or unexecuted partitions " + ", ".join(f"{s}={n}" for s, n in bad.items()))
        if not states:
            reasons.append("never evaluated")
        matched = any(s.startswith("match") for s in states)
        if matched:
            claim = "none (rule matched)" + ("; coverage incomplete: " + "; ".join(reasons) if reasons else "")
        elif states.get("positive_only") or states.get("positive_only_partial") or rule in POSITIVE_ONLY_RULE_IDS:
            # decided by what the rule can prove *now*, not by cells stored under an older pack: a hunt swept
            # before a rule became positive-only must not render its old no_match_complete as "complete"
            claim = POSITIVE_ONLY_CLAIMS.get(
                rule,
                _po("the rule identifies programs or actions from argv or text"),
            ) + ("; coverage incomplete: " + "; ".join(reasons) if reasons else "")
        elif reasons:
            claim = "unresolved: " + "; ".join(reasons)
        elif states.get("no_match_complete") and not (states.get("not_applicable_no_events") and
                                                      set(states) <= {"not_applicable_no_events"}):
            claim = "complete"
        else:
            claim = "not applicable to the data in scope"
        rows.append({"rule_id": rule, "states": dict(states), "records_evaluated": evaluated[rule],
                     "negative_claim": claim})
    return {"rules": rows}


def coverage_for_hunt(repo: Repo, hunt_id: str) -> dict:
    """Coverage with the hunt's own targets, rule pack and sweep completion applied."""
    h = repo.get_hunt(hunt_id) or {}
    hm = h.get("manifest") or {}
    sweep = repo.latest_audit(hunt_id, "hunt.sweep_summary")
    finished = bool(sweep and (sweep.get("detail") or {}).get("finished", (sweep.get("detail") or {}).get("complete")))
    return _coverage(repo.rule_cells(hunt_id), targets=hm.get("targets"),
                     rule_ids=[p["id"] for p in (hm.get("pack") or {}).get("playbooks", [])],
                     sweep_finished=finished)


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
    pivot_gaps = []
    analyst_flags = []
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
                result = step["result_digest"]
                if result.get("status") in {"partial", "failed"}:
                    pivot_gaps.append({
                        "case_id": case["id"], "step": step["n"], "tool": decision.get("tool"),
                        "status": result.get("status"), "reasons": result.get("reasons") or [],
                        "coverage": result.get("coverage") or [],
                    })
            pivot_steps.append({
                "n": step["n"], "tool": decision.get("tool"), "hypothesis": decision.get("hypothesis"),
                "evidence_ids": decision.get("evidence_ids") or [], "arguments": decision.get("arguments") or {},
                "accepted": bool(step["accepted"]), "rejection": step.get("rejection"),
                "task_id": step.get("task_id"), "result": step.get("result_digest"),
            })
        calls = repo.model_calls(case_id=case["id"])
        conclusion = _case_conclusion(case.get("summary"))
        case_flags = []
        if case["status"] == "fallback_parked":
            stored_flag = (conclusion or {}).get("analyst_flag") or {
                "reason": "validation_fallback",
                "message": "Repeated invalid model output requires analyst review.",
            }
            flag = {"case_id": case["id"], **stored_flag}
            case_flags.append(flag)
            analyst_flags.append(flag)
        case_rows.append({
            "id": case["id"], "title": case["title"], "status": case["status"],
            "priority": case["priority"], "seed_candidate_ids": seed_ids,
            "entities": case["entities"], "hypotheses": case["hypotheses"],
            "steps_used": case["steps_used"], "step_budget": case["step_budget"],
            "pivot_steps": pivot_steps,
            "conclusion": conclusion,
            "analyst_flags": case_flags,
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
            "partial_pivots": len(pivot_gaps),
            "contributed_candidates": len(discovered_ids), "unworked_count": len(unworked),
            "analyst_flags": len(analyst_flags),
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
        "analyst_flags": analyst_flags,
        "incomplete_case_ids": sorted(
            case["id"] for case in case_rows if case["status"] not in CONCLUDED_CASE_STATUSES
        ),
        "pivot_gaps": pivot_gaps,
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
        "coverage": coverage_for_hunt(repo, hunt_id),
        "tasks": {s: n for s, n in tasks},
        "agent": agent or {"status": "unknown"},
        "investigations": _investigations(repo, hunt_id, cands, agent or {"status": "unknown"}),
        "versions": {"pack": hm["pack"]["version"], "normalizer": hm["normalizer"], "policy": hm["policy"],
                     "model": hm["model"], "romulus": hm["romulus_version"]},
        "generated_by": actor,
    }
    broken_inv = _broken_investigation_citations(repo, m["investigations"])
    m["integrity"] = {"broken_citations": broken, "broken_investigation_citations": len(broken_inv),
                      "broken_investigation_event_ids": broken_inv[:50],
                      "finalizable": broken == 0 and not broken_inv}
    return _jsonable(m)


def _broken_investigation_citations(repo: Repo, investigations) -> list[str]:
    """Every evidence/event ID cited anywhere in the investigations section must still resolve to a
    stored typed event; otherwise the report is degraded, not finalizable."""
    cited: set[str] = set()

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ("evidence_ids", "event_ids") and isinstance(v, list):
                    cited.update(x for x in v if isinstance(x, str))
                else:
                    walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(investigations)
    if not cited:
        return []
    found = {e["id"] for e in repo.events_by_ids(sorted(cited))}
    return sorted(cited - found)


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
