"""Build one immutable, versioned ReportManifest from a consistent DB snapshot (spec section 13)."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC

from sqlalchemy import func, select

from romulus.agent.cases import seed_candidate_ids
from romulus.decide.policy import LANE_ORDER
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.report.incidents import build_incident_graph, incident_narrative
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
                 "path records are planned")


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
    "host.interpreter_external_connection": (
        "not assessable by design: positive-only rule (the audit rule set's scope, meaning which syscalls, address "
        "families and ports it records, is not visible in telemetry, so a missing connect() record proves nothing)"
    ),
    "pcap.disguised_script_or_executable": (
        "not assessable by design: positive-only packet-content rule over the HTTP sessions the packet stage selected (a body that does not look like a script or executable proves nothing)"
    ),
    "ioc.indicator_match": (
        "not assessable by design: positive-only indicator lists (names, addresses, domains and fingerprints can change, so a list that matches nothing proves nothing)"
    ),
    "corr.process_network_link": (
        "not assessable by design: positive-only correlation (a join between host connect() records and "
        "network-sensor records that finds nothing proves nothing; each side sees only part of the traffic)"
    ),
}


# A rule may state its own reason. It is the single source of truth and wins over the table above; the table
# remains for rules that state no reason of their own.
_RULE_POSITIVE_ONLY = {cls.id: _po(cls.positive_only_reason) for cls in ALL_PLAYBOOKS
                       if not cls.assures_negative and cls.positive_only_reason}


POSITIVE_ONLY_RULE_IDS = frozenset({cls.id for cls in ALL_PLAYBOOKS if not cls.assures_negative}
                                   | set(POSITIVE_ONLY_CLAIMS))


PCAP_CELL_PREFIX = "arkime-pcap:"


def _scope(cell: dict) -> list[str]:
    """What a cell says it examined, when it says so (the packet stage names its selection)."""
    detail = cell.get("detail") or {}
    if not isinstance(detail, dict) or not detail.get("selection"):
        return []
    out = [f"examined on {cell['target'].removeprefix(PCAP_CELL_PREFIX)}: {detail['selection']}"]
    if isinstance(detail.get("http_sessions_without_body_type"), int):
        out.append(f"{detail['http_sessions_without_body_type']} HTTP session(s) there had no body type and were "
                   "outside that selection")
    return out


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
    scope: dict[str, list[str]] = defaultdict(list)
    for c in cells:
        by_rule[c["rule_id"]][c["state"]] += 1
        if c["target"] != "*":
            evaluated[c["rule_id"]] += c["evaluated"] or 0
            # packet-stage cells are written per source target as "arkime-pcap:<target>"
            rule_targets[c["rule_id"]].add(c["target"].removeprefix(PCAP_CELL_PREFIX))
        scope[c["rule_id"]] += _scope(c)
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
            reasons.append("partial, failed or unexecuted partitions "
                           + ", ".join(f"{s}={n}" for s, n in sorted(bad.items())))
        if not states:
            reasons.append("never evaluated")
        matched = any(s.startswith("match") for s in states)
        if matched:
            claim = "none (rule matched)" + "".join(f"; {s}" for s in dict.fromkeys(scope[rule])) \
                + ("; coverage incomplete: " + "; ".join(reasons) if reasons else "")
        elif states.get("positive_only") or states.get("positive_only_partial") or rule in POSITIVE_ONLY_RULE_IDS:
            # decided by what the rule can prove *now*, not by cells stored under an older pack: a hunt swept
            # before a rule became positive-only must not render its old no_match_complete as "complete"
            base = (_RULE_POSITIVE_ONLY.get(rule) or POSITIVE_ONLY_CLAIMS.get(rule)
                    or _po("the rule identifies programs or actions from argv or text"))
            claim = base + "".join(f"; {s}" for s in dict.fromkeys(scope[rule])) \
                + ("; coverage incomplete: " + "; ".join(reasons) if reasons else "")
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


def _expansion_investigations(repo: Repo, hunt_id: str, audit: dict) -> dict:
    anchors = repo.expansion_anchors(hunt_id)
    links = repo.expansion_links(hunt_id)
    by_status = {
        status: [row["id"] for row in anchors if row["status"] == status]
        for status in ("expanded_complete", "expanded_partial", "unexpanded", "pending")
    }
    return {
        "summary": {
            "status": audit.get("status", "unknown"), "mode": "deterministic_expansion",
            "anchors": len(anchors), "links": len(links),
            "unworked_count": len(by_status["unexpanded"] + by_status["pending"]),
            "partial_links": sum(row["status"] != "complete" for row in links),
        },
        "anchor_accounting": {
            **by_status,
            "anchors": [{
                "id": row["id"], "candidate_id": row["candidate_id"], "depth": row["depth"],
                "parent_anchor_id": row["parent_anchor_id"], "status": row["status"],
                "reasons": row["reasons"],
            } for row in anchors],
        },
        "link_accounting": [{
            "id": row["id"], "anchor_id": row["anchor_id"], "link_type": row["link_type"],
            "strength": row["strength"], "status": row["status"], "evidence_ids": row["evidence_ids"],
            "reasons": row["reasons"],
        } for row in links],
        "model_contribution": {"model_calls": 0, "pivot_steps": 0, "pivot_proposals": 0,
                               "candidate_ids": []},
        "seed_partition": {"concluded": [], "assigned_unfinished": [], "unassigned": []},
        "unworked_seed_ids": by_status["unexpanded"] + by_status["pending"],
        "analyst_flags": [], "incomplete_case_ids": [], "pivot_gaps": [], "cases": [],
    }


def _investigations(repo: Repo, hunt_id: str, candidates: list[dict], agent: dict) -> dict:
    hunt = repo.get_hunt(hunt_id) or {}
    hunt_manifest = hunt.get("manifest") or {}
    agent_mode = agent.get("mode") or hunt_manifest.get("agent_mode") or "model"
    cases = repo.cases(hunt_id)
    expansion_audit = repo.latest_audit(hunt_id, "hunt.expansion_summary")
    if expansion_audit and not cases and (agent.get("mode") in (None, "off") or agent.get("status") == "disabled"):
        return _expansion_investigations(repo, hunt_id, expansion_audit.get("detail") or {})
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
    deterministic_fallbacks = 0
    constraint_defects = 0
    menu_hidden_total = 0
    for case in cases:
        steps = repo.case_steps(case["id"])
        chosen_options = []
        capped_steps = 0
        case_hidden_options = 0
        for step in steps:
            decision = step.get("decision") or {}
            hidden = int(decision.get("menu_hidden_count") or 0)
            if hidden:
                capped_steps += 1
                case_hidden_options += hidden
            if decision.get("action") == "constraint_defect":
                constraint_defects += 1
            description = decision.get("option_description")
            if decision.get("chosen_option") and description:
                fallback = bool(decision.get("deterministic_fallback"))
                deterministic_fallbacks += int(fallback)
                chosen_options.append({
                    "n": step["n"], "id": decision["chosen_option"],
                    "description": description, "agent_mode": decision.get("agent_mode") or agent_mode,
                    "deterministic_fallback": fallback,
                    "fallback_note": decision.get("fallback_note") or "",
                })
        menu_hidden_total += case_hidden_options
        seed_ids = [seed_id for seed_id in seed_candidate_ids(steps) if seed_id in seed_candidates]
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
            "chosen_options": chosen_options,
            "menu_cap": {"steps_capped": capped_steps, "hidden_options": case_hidden_options},
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
            "mode": agent_mode,
            "cases": len(case_rows), "model_calls": total_calls, "pivots": executed_pivots,
            "pivot_proposals": pivot_proposals,
            "partial_pivots": len(pivot_gaps),
            "contributed_candidates": len(discovered_ids), "unworked_count": len(unworked),
            "analyst_flags": len(analyst_flags),
            "deterministic_fallbacks": agent.get("deterministic_fallbacks", deterministic_fallbacks),
            "constraint_defects": agent.get("constraint_defects", constraint_defects),
            "menu_hidden_options": menu_hidden_total,
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


def investigations_for_hunt(repo: Repo, hunt_id: str) -> dict:
    """Shared live/report projection for every investigator summary renderer."""
    agent_audit = repo.latest_audit(hunt_id, "hunt.agent_summary")
    agent = agent_audit["detail"] if agent_audit else {"status": "unknown"}
    return _investigations(repo, hunt_id, repo.candidates(hunt_id), agent)


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
            "source_anchor_id": c.get("source_anchor_id"),
            "source_link_id": c.get("source_link_id"),
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
    incident_graph = build_incident_graph(repo, hunt_id, findings)
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
        "incident_graph": incident_graph,
        # an analyst's asserted relations: shown as assertions, never as observed or inferred links
        "analyst_links": [{"id": a["id"], "from_finding": a["from_finding"], "to_finding": a["to_finding"],
                           "relation": a["relation"], "note": a["note"], "actor": a["actor"],
                           "created_at": str(a["created_at"]), "status": "analyst assertion, not proven"}
                          for a in repo.analyst_links(hunt_id)],
        "versions": {"pack": hm["pack"]["version"], "normalizer": hm["normalizer"], "policy": hm["policy"],
                     "model": hm["model"], "romulus": hm["romulus_version"]},
        "generated_by": actor,
    }
    broken_inv = _broken_investigation_citations(repo, m["investigations"])
    broken_incidents = _broken_investigation_citations(repo, incident_graph)
    m["integrity"] = {"broken_citations": broken, "broken_investigation_citations": len(broken_inv),
                      "broken_investigation_event_ids": broken_inv[:50],
                      "broken_incident_citations": len(broken_incidents),
                      "broken_incident_event_ids": broken_incidents[:50],
                      "finalizable": broken == 0 and not broken_inv and not broken_incidents}
    return _jsonable(m)


def _content_candidate_key(repo: Repo, candidate: dict) -> str:
    raw_keys = set()
    for row in repo.events_by_ids(candidate["event_ids"]):
        for reference in row["event"].get("raw", []):
            raw_keys.add(f"{reference['target']}/{reference['native_id']}")
    evidence_identity = candidate.get("group_key") or sorted(raw_keys) or sorted(candidate["event_ids"])
    return "F-" + digest({
        "rule_id": candidate["rule_id"], "evidence_identity": evidence_identity,
    })[:20]


def _as_utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def canonical_manifest(repo: Repo, hunt_id: str, actor: str = "canonical") -> dict:
    """Return a cross-hunt deterministic report projection with content-scoped identities."""
    manifest = build_manifest(repo, hunt_id, actor)
    candidates = repo.candidates(hunt_id)
    candidate_keys = {row["id"]: _content_candidate_key(repo, row) for row in candidates}
    candidate_rows = {row["id"]: row for row in candidates}
    link_rows = repo.expansion_links(hunt_id)
    link_keys = {}
    link_windows = {}
    for row in link_rows:
        anchor = candidate_rows.get(row["anchor_id"])
        anchor_key = candidate_keys.get(row["anchor_id"], row["anchor_id"])
        anchor_ts = _as_utc(anchor["ts"]) if anchor is not None else _as_utc(row["window_start"])
        offsets = {
            "start_seconds": (_as_utc(row["window_start"]) - anchor_ts).total_seconds(),
            "end_seconds": (_as_utc(row["window_end"]) - anchor_ts).total_seconds(),
        }
        link_keys[row["id"]] = "L-" + digest({
            "anchor": anchor_key, "link_type": row["link_type"],
            "window_offsets": offsets, "key": row["key"],
        })[:20]
        link_windows[row["id"]] = {"label": row["window_label"], **offsets}

    incident_keys = {}
    for incident in manifest["incident_graph"]["incidents"]:
        members = sorted(candidate_keys[item] for item in incident["finding_ids"])
        incident_keys[incident["id"]] = "I-" + digest(members)[:20]
    case_keys = {}
    for case in manifest["investigations"].get("cases", []):
        case_keys[case["id"]] = "C-" + digest({
            "seed_candidate_keys": sorted(candidate_keys.get(item, item)
                                             for item in case.get("seed_candidate_ids", [])),
            "title": case.get("title"), "entities": case.get("entities", []),
        })[:20]
    identity_map = {**candidate_keys, **link_keys, **incident_keys, **case_keys}
    drop_keys = {"started_at", "ended_at", "created_at", "updated_at", "duration_ms",
                 "task_id", "task_ids", "at"}

    def canonicalize(value):
        if isinstance(value, dict):
            return {
                key: canonicalize(item)
                for key, item in value.items()
                if key not in drop_keys
            }
        if isinstance(value, list):
            return [canonicalize(item) for item in value]
        if isinstance(value, str):
            if value in identity_map:
                return identity_map[value]
            for scoped, content in sorted(identity_map.items(), key=lambda item: (-len(item[0]), item[0])):
                value = value.replace(scoped, content)
            return value
        return value

    canonical = canonicalize(manifest)
    canonical["schema"] = "canonical-report-manifest@1"
    canonical["hunt"].pop("id", None)
    graph = canonical["incident_graph"]
    for source, projected in zip(manifest["incident_graph"]["links"], graph["links"], strict=True):
        projected["window"] = link_windows.get(source["id"], projected.get("window"))
    graph["edges"] = [{
        "pair": [candidate_keys[edge["from"]], candidate_keys[edge["to"]]],
        "link_key": link_keys[edge["link_id"]],
        "link_type": edge["link_type"], "style": edge["style"],
    } for edge in manifest["incident_graph"]["edges"]]
    canonical["findings"].sort(key=lambda finding: finding["id"])
    for finding in canonical["findings"]:
        gates = finding.get("gates") or {}
        if gates.get("_context_reaches"):        # stored sorted by hunt-scoped link ids; re-sort by content
            gates["_context_reaches"] = sorted(
                gates["_context_reaches"],
                key=lambda reach: json.dumps(reach, sort_keys=True, separators=(",", ":"), default=str),
            )
    observed_at = {finding["id"]: finding["observed_at"] for finding in canonical["findings"]}
    canonical_findings = {finding["id"]: finding for finding in canonical["findings"]}
    graph["nodes"].sort(key=lambda node: node["id"])
    for link in graph["links"]:
        link["target_finding_ids"] = sorted(link["target_finding_ids"])
    graph["links"].sort(key=lambda link: link["id"])
    graph["edges"].sort(key=lambda edge: (edge["pair"], edge["link_key"]))
    for incident in graph["incidents"]:
        incident["finding_ids"] = sorted(incident["finding_ids"])
        incident["timeline"] = sorted(
            incident["timeline"], key=lambda item: (observed_at.get(item, ""), item),
        )
        incident["link_ids"] = sorted(incident["link_ids"])
        member_ids = set(incident["finding_ids"])
        incoming = {
            edge["pair"][1] for edge in graph["edges"]
            if edge["style"] == "observed" and set(edge["pair"]) <= member_ids
        }
        entry_candidates = member_ids - incoming
        incident["entry_point"] = min(
            entry_candidates or member_ids,
            key=lambda item: (observed_at.get(item, ""), item),
        )
        open_ends = incident["open_ends"]
        for key in ("unexpanded_anchors", "pending_anchors", "partial_anchors", "unresolved_links"):
            open_ends[key] = sorted(
                open_ends.get(key, []),
                key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
            )
        # the narrative follows the timeline: rebuild it from the content-ordered incident
        incident["narrative"] = incident_narrative(incident, canonical_findings, [
            {"from": edge["pair"][0], "to": edge["pair"][1], "link_id": edge["link_key"],
             "link_type": edge["link_type"], "style": edge["style"]} for edge in graph["edges"]
        ])
    graph["incidents"].sort(key=lambda incident: incident["id"])
    investigations = canonical["investigations"]
    for key in ("unworked_seed_ids", "incomplete_case_ids"):
        investigations[key] = sorted(investigations.get(key, []))
    for key in ("concluded", "assigned_unfinished", "unassigned"):
        investigations["seed_partition"][key] = sorted(
            investigations["seed_partition"].get(key, []),
        )
    investigations["model_contribution"]["candidate_ids"] = sorted(
        investigations["model_contribution"].get("candidate_ids", []),
    )
    anchor_accounting = investigations.get("anchor_accounting")
    if anchor_accounting:
        for key in ("expanded_complete", "expanded_partial", "unexpanded", "pending"):
            anchor_accounting[key] = sorted(anchor_accounting.get(key, []))
        anchor_accounting["anchors"] = sorted(
            anchor_accounting.get("anchors", []), key=lambda item: item["id"],
        )
        investigations["link_accounting"] = sorted(
            investigations.get("link_accounting", []), key=lambda item: item["id"],
        )
    return _jsonable(canonical)


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
