"""Build one immutable, versioned ReportManifest from a consistent DB snapshot (spec section 13)."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import UTC

from sqlalchemy import func, select

from romulus.agent.cases import seed_candidate_ids
from romulus.agent.provider import egress_banners
from romulus.decide.policy import LANE_ORDER
from romulus.detect.metadata import hunt_rule_metadata, is_sigma_id, pinned_rule_ids
from romulus.detect.netdef import recorded_view
from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.hunt.publish import subject_event_ids
from romulus.report.incidents import build_incident_graph, incident_narrative
from romulus.store import schema as t
from romulus.store.db import digest, utcnow, write_txn
from romulus.store.repo import Repo, raw_id

MANIFEST_SCHEMA = "report-manifest@1"
REPORTABLE_LANES = ("urgent", "high", "lead")
CONCLUDED_CASE_STATUSES = {"closed", "parked", "escalated"}
LEGACY_AGENT_MODE_KEY = "agent_mode"


def _jsonable(v):
    return json.loads(json.dumps(v, default=str))


def _citations(repo: Repo, cand: dict) -> list[dict]:
    """Resolve every cited event to retained raw records (or mark the citation broken)."""
    events = {e["id"]: e for e in repo.citation_events(cand["hunt_id"], cand["event_ids"])}
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
    "partial", "failed", "omitted_budget",
)
_NO_ASSURANCE = ("no rule in this pack can show absence for this behavior; a full search from kernel records "
                 "needs a typed inventory of what the host's audit rules record, which the telemetry does not carry")


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
_INDICATOR_GAP = re.compile(r'^Indicator kind ([a-z0-9_]+) cannot be searched in (\d+) delivered record\(s\):')


def _scope(cell: dict) -> list[str]:
    """What a cell says it examined, when it says so (the packet stage names its selection)."""
    detail = cell.get("detail") or {}
    if not isinstance(detail, dict):
        return []
    out = [str(reason) for reason in detail.get('reasons', [])
           if str(reason).startswith('Indicator kind ') and not _INDICATOR_GAP.match(str(reason))]
    if not detail.get('selection'):
        return out
    out.append(f"examined on {cell['target'].removeprefix(PCAP_CELL_PREFIX)}: {detail['selection']}")
    if isinstance(detail.get("http_sessions_without_body_type"), int):
        out.append(f"{detail['http_sessions_without_body_type']} HTTP session(s) there had no body type and were "
                   "outside that selection")
    return out


def _gap_reasons(cell: dict) -> list[str]:
    """Why a cell is unresolved, from what the stage that wrote it recorded."""
    detail = cell.get("detail") if isinstance(cell.get("detail"), dict) else {}
    reasons = [str(r) for r in detail.get("reasons") or [] if r]
    if detail.get("error"):
        reasons.append(f"error: {detail['error']}")
    missing = detail.get("missing_required")
    if isinstance(missing, int) and missing and not any(r.startswith("missing_required") for r in reasons):
        reasons.append(f"missing_required={missing}: records lacked a field this rule needs")
    if cell["state"] == "planned":
        reasons.append("planned but never executed")
    return reasons or [f"{cell['state']}: no reason recorded"]


def _gaps(cells: list[dict], targets: list[str] | None = None, rule_ids: list[str] | None = None) -> list[dict]:
    """Every (target, partition) with an unresolved cell, the rules it leaves unresolved and why, plus every
    hunt target with no cell at all. Nothing is capped: each gap is listed, whatever their number."""
    rules_at: dict[tuple, set] = defaultdict(set)
    gaps: dict[tuple, dict] = {}
    covered = {c["target"].removeprefix(PCAP_CELL_PREFIX) for c in cells}
    every_rule = sorted(set(rule_ids or []) | {c["rule_id"] for c in cells})
    for target in sorted(set(targets or []) - covered):
        gaps[(target, "")] = {"target": target, "partition": "whole hunt window",
                              "rules": dict.fromkeys(every_rule, "not evaluated"),
                              "reasons": ["no coverage was recorded for this target"]}
        rules_at[(target, "")] = set(every_rule)
    for c in cells:
        key = (c["target"], c["partition"])
        rules_at[key].add(c["rule_id"])
        if c["state"] not in UNRESOLVED_STATES:
            continue
        gap = gaps.setdefault(key, {"target": c["target"], "partition": c["partition"], "rules": {},
                                    "reasons": []})
        gap["rules"][c["rule_id"]] = c["state"]
        gap["reasons"] += [r for r in _gap_reasons(c) if r not in gap["reasons"]]
    out = []
    for key in sorted(gaps):
        gap = gaps[key]
        gap["rules"] = dict(sorted(gap["rules"].items()))
        gap["reasons"] = sorted(gap["reasons"])
        gap["every_rule_there"] = set(gap["rules"]) == rules_at[key]
        out.append(gap)
    return out


def _not_assessed(hunt_manifest: dict, sweep_detail: dict) -> list[dict]:
    """Data in scope that no rule evaluated: datasets the sweep did not retrieve, and retrieved records that
    no normalizer turned into a typed event. Listed with counts where known, never counted as evaluated."""
    stats = sweep_detail.get("stats") or {}
    profiles = hunt_manifest.get("source_profiles") or {}
    out = []

    def skip_explanation(reason: str) -> str:
        if reason == "duplicate typed event across source partitions":
            return "typed event deduplicated across source partitions; its additional raw provenance was retained"
        if reason == "record_id reused (log cleared or reverted)":
            return "typed Windows events retained separately after record_id reuse (log cleared or reverted)"
        return f"retrieved but not turned into a typed event: {reason}"
    for target, retrieved in sorted((stats.get("dataset_filter") or {}).items()):
        inventory = (profiles.get(target) or {}).get("datasets")
        if not isinstance(inventory, dict):
            out.append({"target": target, "dataset": f"any dataset other than {', '.join(retrieved)}",
                        "records": None, "count_scope": "unknown: the hunt manifest has no dataset inventory",
                        "reason": "not retrieved by the sweep"})
            continue
        for dataset, count in sorted(inventory.items()):
            if dataset not in retrieved:
                out.append({"target": target, "dataset": dataset, "records": count,
                            "count_scope": "whole index at source preflight, not only the hunt window",
                            "reason": "not retrieved by the sweep: no normalizer reads this dataset, so no rule "
                                      "evaluates it"})
        if not (profiles.get(target) or {}).get("datasets_complete", True):
            out.append({"target": target, "dataset": f"any dataset other than {', '.join(retrieved)}",
                        "records": None,
                        "count_scope": "unknown: the source preflight could not list every dataset of the index",
                        "reason": "not retrieved by the sweep"})
    for target, classes in sorted((stats.get("windows_unassessed") or {}).items()):
        for event_class in classes:
            if event_class.get("uncatalogued"):
                if event_class.get("overflow"):
                    dataset = f"{event_class['classes']:,} additional uncatalogued Windows event classes"
                    reason = "inventory rows omitted after the bounded category limit"
                else:
                    dataset = (
                        f"{event_class['channel']}|{event_class['provider']}|{event_class['event_id']}"
                    )
                    reason = "uncatalogued Windows event class was not retrieved or evaluated"
                out.append({
                    "target": target,
                    "dataset": dataset,
                    "records": event_class["records"],
                    "count_scope": "source inventory for the hunt window; records were not retrieved",
                    "reason": reason,
                })
                continue
            out.append({
                "target": target,
                "dataset": (
                    f"{event_class['channel']}|{event_class['provider']}|{event_class['event_id']}"
                ),
                "records": event_class["records"],
                "count_scope": "records retrieved in the hunt window",
                "reason": (
                    f"catalogued Windows {event_class['family']} event class has no rule reader in this pack"
                ),
            })
    scoped_skips = stats.get("skips_by_target") or {}
    if scoped_skips:
        scoped_totals: Counter = Counter()
        for target, reasons in sorted(scoped_skips.items()):
            for reason, count in sorted(reasons.items()):
                scoped_totals[reason] += count
                out.append({"target": target, "dataset": None, "records": count,
                            "count_scope": "records retrieved in the hunt window",
                            "reason": skip_explanation(reason)})
        global_scoped = stats.get("skips_scoped_global")
        if isinstance(global_scoped, dict):
            scoped_totals = Counter(global_scoped)
        for reason, count in sorted((stats.get("skips") or {}).items()):
            remainder = count - scoped_totals[reason]
            if remainder > 0:
                out.append({"target": "all sweep targets", "dataset": None, "records": remainder,
                            "count_scope": "records retrieved in the hunt window",
                            "reason": skip_explanation(reason)})
    else:
        for reason, count in sorted((stats.get("skips") or {}).items()):
            out.append({"target": "all sweep targets", "dataset": None, "records": count,
                        "count_scope": "records retrieved in the hunt window",
                        "reason": skip_explanation(reason)})
    return out


def _coverage(cells: list[dict], targets: list[str] | None = None, rule_ids: list[str] | None = None,
              sweep_finished: bool = True, metadata=None) -> dict:
    """Per-rule search result: what each rule searched, never a claim that nothing is there. 'searched in full'
    requires: the sweep finished, every manifest target has cells for the rule, no cell is planned/failed/partial,
    and at least one evaluated partition with no match. Anything less is 'searched in part' with the reason;
    absence of data is 'no data in scope'. Every partly searched (target, partition) is also listed as a gap with
    its reasons."""
    cells = [c for c in cells if c["state"] != "split"]          # superseded by their children
    by_rule: dict[str, Counter] = defaultdict(Counter)
    evaluated: Counter = Counter()
    rule_targets: dict[str, set] = defaultdict(set)
    scope: dict[str, list[str]] = defaultdict(list)
    indicator_gaps = Counter()
    for c in cells:
        by_rule[c["rule_id"]][c["state"]] += 1
        if c["target"] != "*":
            evaluated[c["rule_id"]] += c["evaluated"] or 0
            # packet-stage cells are written per source target as "arkime-pcap:<target>"
            rule_targets[c["rule_id"]].add(c["target"].removeprefix(PCAP_CELL_PREFIX))
        scope[c["rule_id"]] += _scope(c)
        detail = c.get('detail') or {}
        if c['target'] != '*' and isinstance(detail, dict):
            for reason in detail.get('reasons', []):
                if parsed := _INDICATOR_GAP.match(str(reason)):
                    kind, count = parsed.groups()
                    indicator_gaps[c['rule_id'], c['target'].removeprefix(PCAP_CELL_PREFIX), kind] += int(count)
    for (rule_id, target, kind), count in sorted(indicator_gaps.items()):
        scope[rule_id].append(f'Indicator kind {kind} cannot be searched in {count} delivered record(s): '
            f'no complete typed value was available; no negative result is asserted. Target: {target}.')
    for rid in rule_ids or []:
        by_rule.setdefault(rid, Counter())
    rows = []
    for rule, states in sorted(by_rule.items()):
        dynamic = (metadata or {}).get(rule)
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
        elif set(states) == {"not_applicable_no_events"} and not reasons:
            claim = "no data in scope for this rule"
        elif (states.get("positive_only") or states.get("positive_only_partial") or rule in POSITIVE_ONLY_RULE_IDS
              or dynamic is not None and not dynamic.assures_negative):
            # decided by what the rule can prove *now*, not by cells stored under an older pack: a hunt swept
            # before a rule became positive-only must not render its old no_match_complete as "complete"
            base = (_po(dynamic.positive_only_reason) if dynamic is not None and dynamic.positive_only_reason else
                    _RULE_POSITIVE_ONLY.get(rule) or POSITIVE_ONLY_CLAIMS.get(rule)
                    or _po("the rule identifies programs or actions from argv or text"))
            claim = base + "".join(f"; {s}" for s in dict.fromkeys(scope[rule])) \
                + ("; coverage incomplete: " + "; ".join(reasons) if reasons else "")
        elif reasons:
            claim = "searched in part: " + "; ".join(reasons)
        elif states.get("no_match_complete") and not (states.get("not_applicable_no_events") and
                                                      set(states) <= {"not_applicable_no_events"}):
            claim = f"searched in full: {evaluated[rule]} record(s) evaluated, none matched"
        else:
            claim = "no data in scope for this rule"
        rows.append({"rule_id": rule, "states": dict(states), "records_evaluated": evaluated[rule],
                     "search_result": claim})
    return {"rules": rows, "gaps": _gaps(cells, targets, rule_ids)}


def coverage_for_hunt(repo: Repo, hunt_id: str) -> dict:
    """Coverage with the hunt's own targets, rule pack and sweep completion applied."""
    h = repo.get_hunt(hunt_id) or {}
    hm = h.get("manifest") or {}
    sweep = repo.latest_audit(hunt_id, "hunt.sweep_summary")
    detail = (sweep or {}).get("detail") or {}
    finished = bool(sweep and detail.get("finished", detail.get("complete")))
    coverage = _coverage(repo.rule_cells(hunt_id), targets=hm.get("targets"),
                         rule_ids=sorted(pinned_rule_ids(hm)),
                         sweep_finished=finished, metadata=hunt_rule_metadata(repo, manifest=hm))
    coverage["not_assessed"] = _not_assessed(hm, detail)
    coverage["baseline"] = _baseline_coverage(repo, hunt_id, hm)
    visibility = repo.latest_audit(hunt_id, "hunt.zeek_visibility")
    if visibility:
        from itertools import islice
        detail = dict(visibility["detail"])
        detail["preview"] = list(islice(repo.zeek_visibility_rows(hunt_id, detail["snapshot"]["sha256"]), 50))
        coverage["zeek_visibility"] = detail
    return coverage


def _baseline_coverage(repo: Repo, hunt_id: str, hunt_manifest: dict) -> dict:
    """Bounded report projection of the immutable baseline snapshot and per-spec verdict health."""
    config = hunt_manifest.get("baseline") or {}
    declared = config.get("specs") or []
    snapshot = repo.baseline_snapshot(hunt_id)
    audit = repo.latest_audit(hunt_id, "hunt.baseline_summary")
    summary = (audit or {}).get("detail") or {}
    verdicts = repo.baseline_observation_verdict_counts(hunt_id)
    specs = []
    for declared_spec in declared:
        spec_id = declared_spec["id"]
        target_coverage = {
            key.split("|", 1)[0]: value
            for key, value in ((snapshot or {}).get("coverage") or {}).items()
            if key.endswith(f"|{spec_id}")
        }
        statuses = {item.get("status") for item in target_coverage.values()}
        stage_stats = (summary.get("specs") or {}).get(spec_id) or {}
        unresolved = int((verdicts.get(spec_id) or {}).get("unresolved", 0))
        if (snapshot is None or unresolved or stage_stats.get("history_failure")
                or stage_stats.get("window_failure") or statuses - {"resolved", "shortened"}):
            status = "unresolved"
        elif "shortened" in statuses:
            status = "shortened"
        else:
            status = "resolved"
        specs.append({
            "id": spec_id, "version": declared_spec["version"], "status": status,
            "unresolved_count": unresolved, "verdicts": verdicts.get(spec_id) or {},
            "targets": target_coverage,
        })
    return {
        "snapshot_digest": (snapshot or {}).get("digest") or summary.get("snapshot_digest"),
        "snapshot_status": (snapshot or {}).get("status") or "not_frozen",
        "stage_status": summary.get("status", "not_run"),
        "specs": specs,
    }


def coverage_for_rules(repo: Repo, hunt_id: str, rule_ids: set[str]) -> dict:
    """Canonical coverage using only the requested rule rows from SQL."""
    h = repo.get_hunt(hunt_id) or {}
    hm = h.get("manifest") or {}
    sweep = repo.latest_audit(hunt_id, "hunt.sweep_summary")
    detail = (sweep or {}).get("detail") or {}
    finished = bool(sweep and detail.get("finished", detail.get("complete")))
    coverage = _coverage(
        repo.rule_cells(hunt_id, rule_ids), targets=hm.get("targets"),
        rule_ids=sorted(rule_ids), sweep_finished=finished, metadata=hunt_rule_metadata(repo, manifest=hm),
    )
    presence = repo.rule_presence_counts(
        hunt_id, {(gap["target"], gap["partition"]) for gap in coverage["gaps"]},
    )
    for gap in coverage["gaps"]:
        key = (gap["target"], gap["partition"])
        if key in presence:
            gap["every_rule_there"] = len(gap["rules"]) == presence[key]
    coverage["not_assessed"] = _not_assessed(hm, detail)
    return coverage


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
    # created_at reflects runtime scheduling, not report identity. Emit stable content order even before the
    # whole-manifest canonicalizer so this helper cannot leak execution order to another caller.
    links = sorted(repo.expansion_links(hunt_id), key=lambda row: row["id"])
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
            "source_queries": audit.get("source_queries"), "budget": audit.get("budget"),
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
    candidates = [row for row in candidates if row.get("provenance", "deterministic") != "agent"]
    hunt = repo.get_hunt(hunt_id) or {}
    hunt_manifest = hunt.get("manifest") or {}
    legacy_mode = agent.get("mode") or _legacy_mode_value(hunt_manifest)
    if legacy_mode is None:
        configured_agent = hunt_manifest.get("ai_agent")
        legacy_mode = "model" if not isinstance(configured_agent, dict) or configured_agent.get("requested", True) else "off"
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
                    "description": description,
                    LEGACY_AGENT_MODE_KEY: _legacy_mode_value(decision) or legacy_mode,
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
            "mode": legacy_mode,
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


def _discovery_origin(candidate: dict) -> dict:
    """Older evidence-view rows kept discovery ownership in their gate metadata."""
    origin = (candidate.get("gate_results") or {}).get("_evidence_view_origin") or {}
    return {**candidate, **{name: candidate.get(name) if candidate.get(name) is not None else origin.get(name)
                            for name in ("source_case_id", "source_anchor_id", "source_link_id")}}


def investigations_for_hunt(repo: Repo, hunt_id: str) -> dict:
    """Shared live/report projection for every investigator summary renderer."""
    agent_audit = repo.latest_audit(hunt_id, "hunt.agent_summary")
    agent = agent_audit["detail"] if agent_audit else {"status": "unknown"}
    return _investigations(repo, hunt_id, [_discovery_origin(row) for row in repo.candidates(hunt_id)], agent)


def build_manifest(repo: Repo, hunt_id: str, actor: str) -> dict:
    h = repo.get_hunt(hunt_id)
    if h is None:
        raise KeyError(hunt_id)
    metadata = hunt_rule_metadata(repo, manifest=h['manifest'])
    cands = [_discovery_origin(row) for row in repo.candidates(hunt_id)]
    cands.sort(key=lambda c: (LANE_ORDER.get(c["lane"], 9), -c["priority"], str(c["ts"])))
    findings = []
    for c in cands:
        if c["lane"] not in REPORTABLE_LANES:
            continue
        disp = repo.dispositions(c["id"])
        gates = dict(c["gate_results"])
        notes = gates.pop("_notes", [])
        attack = gates.pop('_attack', [])
        gates.pop("aggregate_summary", None)
        findings.append({
            "id": c["id"], "lane": c["lane"], "severity": c["severity"], "confidence": c["confidence"],
            "priority": c["priority"], "priority_reasons": c["priority_reasons"], "rule_id": c["rule_id"],
            "rule_version": c["rule_version"], "claim": c["claim"], "claim_type": c["claim_type"],
            "observed_at": str(c["ts"]) if c["ts"] is not None else None,
            "entities": c["entities"], "predicate_fields": c["predicate_fields"],
            "gates": gates, "notes": notes, "benign_alternatives": c["benign_alternatives"],
            "next_checks": c["next_checks"], "citations": _citations(repo, c),
            "source_case_id": c.get("source_case_id"),
            "source_anchor_id": c.get("source_anchor_id"),
            "source_link_id": c.get("source_link_id"),
            "provenance": c.get("provenance", "deterministic"),
            "agent_hypothesis_id": c.get("agent_hypothesis_id"),
            "analyst_status": disp[-1]["status"] if disp else "new",
            "disposition_history": [{"actor": d["actor"], "at": str(d["at"]), "status": d["status"],
                                     "note": d["note"]} for d in disp],
        })
        rule = metadata.get(c['rule_id'])
        if is_sigma_id(c['rule_id']) and rule is not None:
            findings[-1]['rule_title'] = rule.title
        if attack:
            findings[-1]['attack'] = attack
        if c.get("provenance") == "agent":
            findings[-1]["label"] = "Agent finding"
        if "_fleet_host_count" in gates:
            findings[-1]["fleet_hosts"] = repo.snapshot_candidate_hosts(
                c["id"], hunt_id, expected_count=gates["_fleet_host_count"],
                complete=gates.get("_fleet_hosts_complete", False), expected_candidate=c)
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
        "internal_networks": internal_networks_view(repo, hunt_id, hm),
        "lane_counts": dict(lane_counts),
        "findings": findings,
        "context_items": lane_counts.get("context", 0),
        "coverage": coverage_for_hunt(repo, hunt_id),
        "tasks": {s: n for s, n in tasks},
        "agent": agent or {"status": "unknown"},
        "ai_agent": _ai_agent(repo, hunt_id, hm),
        "ai_assessment": _ai_assessment(repo, hunt_id),
        "banners": egress_banners(hm.get("ai_agent"), repo.agent_usage(hunt_id)),
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
    lists = hm.get('indicator_lists') or {}
    if lists.get('applied') or lists.get('excluded'):
        m['versions']['indicator_lists'] = {
            'excluded_expired_values': sum(pin.get('excluded_expired_values', 0) for pin in lists.get('applied', [])),
            'applied': [{key: pin.get(key, 0 if key == 'excluded_expired_values' else None)
                         for key in ('id', 'version', 'digest', 'excluded_expired_values')}
                        for pin in lists.get('applied', [])],
            'excluded': [{key: pin[key] for key in ('id', 'version', 'digest', 'reason') if key in pin}
                         for pin in lists.get('excluded', [])],
        }
    sigma = hm.get('sigma_rules') or {}
    if sigma.get('applied'):
        m['versions']['sigma_rules'] = {'digest': sigma.get('digest'), 'applied': [
            {key: pin[key] for key in ('id', 'version', 'digest') if key in pin} for pin in sigma['applied']]}
    broken_inv = _broken_investigation_citations(repo, m["investigations"])
    broken_incidents = _broken_investigation_citations(repo, incident_graph)
    m["integrity"] = {"broken_citations": broken, "broken_investigation_citations": len(broken_inv),
                      "broken_investigation_event_ids": broken_inv[:50],
                      "broken_incident_citations": len(broken_incidents),
                      "broken_incident_event_ids": broken_incidents[:50],
                      "finalizable": broken == 0 and not broken_inv and not broken_incidents}
    fleet_gaps = sum(not finding["fleet_hosts"]["complete"] for finding in findings if "fleet_hosts" in finding)
    if fleet_gaps:
        m["integrity"]["incomplete_fleet_host_lists"] = fleet_gaps
        m["integrity"]["finalizable"] = False
    return _jsonable(m)


def internal_networks_view(repo: Repo, hunt_id: str, hunt_manifest: dict) -> dict:
    """The definition the hunt recorded, with the sweep's host-address check and its warning when it ran."""
    view = recorded_view(hunt_manifest.get("internal_networks"))
    sweep = repo.latest_audit(hunt_id, "hunt.sweep_summary")
    check = ((sweep or {}).get("detail") or {}).get("internal_networks")
    if check:
        view = {**view, "host_address_check": check, "warning": check.get("warning")}
    return view


def _ai_agent(repo: Repo, hunt_id: str, hunt_manifest: dict) -> dict:
    """The AI agent's provenance, persisted phase and append-only output summary."""
    configured = dict(hunt_manifest.get("ai_agent") or {})
    configured.pop("budgets", None)
    phase = repo.latest_audit(hunt_id, "hunt.ai_agent_summary")
    usage = repo.agent_usage(hunt_id)
    calls = repo.model_calls(hunt_id)
    shown = {k: usage[k] for k in ("calls", "tokens", "cost_usd", "estimated")}
    shown["billed_failures"] = sum(bool((row.get("options") or {}).get("billed_failure")) for row in calls)
    if usage["models_reported"]:
        shown["models_reported"] = usage["models_reported"]
    run = repo.agent_run(hunt_id)
    hypotheses = []
    for row in repo.agent_hypotheses(hunt_id):
        hypotheses.append({
            "id": row["id"], "status": row["status"], "confidence": row["confidence"],
            "statement": row["statement"], "techniques": row["techniques"], "entity_ids": row["entity_ids"],
            "cites": [{"role": cite["role"], "kind": cite["target_kind"], "id": cite["target_id"]}
                      for cite in repo.agent_hypothesis_cites(hypothesis_id=row["id"])],
            "sessions_run": row["sessions_run"], "questions": row["questions"],
        })
    agent_findings = [row for row in repo.candidates(hunt_id) if row.get("provenance") == "agent"]
    assessments = repo.agent_assessments(hunt_id)
    reason = str((run or {}).get("reason") or "")
    limits_hit = sorted({item.strip() for item in reason.split(";")
                         if item.strip().startswith(("cap:", "budget:"))})
    anchors = repo.expansion_anchors(hunt_id)
    return {
        "requested": bool(configured.get("requested", _legacy_mode_value(hunt_manifest) != "off")),
        "configured": configured,
        "phase": phase["detail"] if phase else {"status": (run or {}).get("state", "unknown")},
        "run": {"state": (run or {}).get("state", "unknown"), "reason": reason or None,
                "prompt_digests": (run or {}).get("prompt_digests") or {},
                "provider": (run or {}).get("provider") or {}},
        "usage": shown,
        "hypotheses": hypotheses,
        "agent_findings": len(agent_findings),
        "agent_links": repo.agent_links(hunt_id),
        "agent_notes": _group_agent_notes(repo.agent_notes(hunt_id)),
        "rule_requests": repo.agent_rule_requests(hunt_id),
        "limits_hit": limits_hit,
        "unworked": {"hypotheses": [row["id"] for row in repo.agent_hypotheses(hunt_id)
                                     if row["status"] == "open" and not row["sessions_run"]],
                      "anchors": [row["id"] for row in anchors if row["status"] in {"unexpanded", "pending"}]},
        "assessment_revision": assessments[-1]["revision"] if assessments else None,
    }


def _legacy_mode_value(record: dict) -> str | None:
    """Read the retired mode field only for stored pre-M6 hunts and case-step rows."""
    return record.get(LEGACY_AGENT_MODE_KEY)


def _group_agent_notes(notes: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in notes:
        grouped[(row["target_kind"], row["target_id"])].append(row)
    return [{"target_kind": kind, "target_id": target_id,
             "notes": [{"id": row["id"], "text": row["text"], "cites": row["cites"],
                        "suspicious_content": row["suspicious_content"]}
                       for row in sorted(rows, key=lambda item: item["id"])]}
            for (kind, target_id), rows in sorted(grouped.items())]


def _ai_assessment(repo: Repo, hunt_id: str) -> dict | None:
    assessments = repo.agent_assessments(hunt_id)
    if assessments:
        row = assessments[-1]
        source = row["source"]
        model = row["model"] or {}
        header = (f"AI-generated hypothesis from the cited evidence. Not confirmed by an analyst. Model: "
                  f"{model.get('provider', 'unknown')}/{model.get('model_reported') or model.get('model_requested') or 'unknown'}."
                  if source == "agent" else
                  f"Template narrative: no AI assessment was produced ({(repo.agent_run(hunt_id) or {}).get('reason') or 'not available'}).")
        return {"source": source, "header": header, "model": model, "body": row["body"],
                "checker": row["checker"], "revision": row["revision"]}
    # Preserve the byte-for-byte renderer output for hunts that predate the persisted agent phase.
    # New hunts always have an agent_run row and receive their deterministic template in this path.
    if repo.agent_run(hunt_id) is None:
        return None
    from romulus.agent.assessment import template_assessment
    reason = (repo.agent_run(hunt_id) or {}).get("reason") or "assessment not available"
    return template_assessment(repo, hunt_id, reason)


def _content_candidate_key(repo: Repo, candidate: dict) -> str:
    """A finding's cross-hunt identity: its rule and its evidence, which is its documented group key or the raw
    records of its subject (the records it is about, not those cited only to support its claim's statements, as the
    candidate id is built), so findings that cite each other's records for context keep identities of their own. A
    candidate stored without `context_event_ids` is about every record it cites."""
    subject = subject_event_ids(candidate)
    raw_keys = set()
    for row in repo.citation_events(candidate["hunt_id"], subject):
        for reference in row["event"].get("raw", []):
            raw_keys.add(f"{reference['target']}/{reference['native_id']}")
    evidence_identity = candidate.get("group_key") or sorted(raw_keys) or sorted(subject)
    return "F-" + digest({
        "rule_id": candidate["rule_id"], "evidence_identity": evidence_identity,
    })[:20]


def _unique_candidate_keys(repo: Repo, candidates: list[dict]) -> dict[str, str]:
    """Every candidate's content identity, made unique: candidates whose rule and evidence still coincide (an older
    hunt's findings that cite each other's records, stored without `context_event_ids`) are told apart by their claim
    and cited records, in that content order, so no published finding shares an id or is merged away."""
    keys = {row["id"]: _content_candidate_key(repo, row) for row in candidates}
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in candidates:
        groups[keys[row["id"]]].append(row)
    for key, rows in groups.items():
        if len(rows) < 2:
            continue
        ordered = sorted(rows, key=lambda row: (row["claim"], sorted(row["event_ids"]), row["id"]))
        for rank, row in enumerate(ordered, 1):
            keys[row["id"]] = f"{key}-{rank}"
    return keys


def _as_utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def canonical_manifest(repo: Repo, hunt_id: str, actor: str = "canonical") -> dict:
    """Return a cross-hunt deterministic projection; AI-only output lives under ``ai``."""
    manifest = build_manifest(repo, hunt_id, actor)
    candidates = repo.candidates(hunt_id)
    candidate_keys = _unique_candidate_keys(repo, candidates)
    candidate_rows = {row["id"]: row for row in candidates}
    link_rows = repo.expansion_links(hunt_id)
    link_keys = {}
    link_windows = {}
    for row in link_rows:
        anchor = candidate_rows.get(row["anchor_id"])
        anchor_key = candidate_keys.get(row["anchor_id"], row["anchor_id"])
        anchor_ts = (_as_utc(anchor["ts"]) if anchor is not None and anchor["ts"] is not None
                     else _as_utc(row["window_start"]))
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
    agent_findings = [row for row in manifest["findings"] if row.get("provenance") == "agent"]
    ai_content = {
        "agent": manifest.get("ai_agent"), "assessment": manifest.get("ai_assessment"),
        "findings": agent_findings,
        "links": (manifest.get("incident_graph") or {}).get("agent_links") or [],
        "hypotheses": ((manifest.get("ai_agent") or {}).get("hypotheses") or []),
        "notes": ((manifest.get("ai_agent") or {}).get("agent_notes") or []),
        "rule_requests": ((manifest.get("ai_agent") or {}).get("rule_requests") or []),
        "banners": manifest.get("banners") or [],
    }
    canonical["ai"] = canonicalize(ai_content)
    deterministic_findings = [row for row in repo.candidates(hunt_id)
                              if row.get("provenance", "deterministic") != "agent"]
    deterministic_views = [row for row in manifest["findings"] if row.get("provenance") != "agent"]
    for row in deterministic_views:
        row.pop("provenance", None)
        row.pop("agent_hypothesis_id", None)
    canonical["findings"] = canonicalize(deterministic_views)
    canonical["lane_counts"] = dict(Counter(row["lane"] for row in deterministic_findings))
    canonical["context_items"] = canonical["lane_counts"].get("context", 0)
    deterministic_graph = build_incident_graph(repo, hunt_id, [
        {"id": row["id"], "lane": row["lane"], "rule_id": row["rule_id"],
         "observed_at": str(row["ts"]) if row["ts"] is not None else None,
         "entities": row.get("entities") or [], "event_ids": row.get("event_ids") or [],
         "citations": [], "source_link_id": row.get("source_link_id")}
        for row in deterministic_findings if row["lane"] in REPORTABLE_LANES
    ], include_agent_links=False)
    canonical["incident_graph"] = canonicalize(deterministic_graph)
    canonical["incident_graph"].pop("agent_links", None)
    canonical.pop("ai_agent", None)
    canonical.pop("ai_assessment", None)
    canonical.pop("banners", None)
    canonical["schema"] = "canonical-report-manifest@1"
    canonical["hunt"].pop("id", None)
    graph = canonical["incident_graph"]
    for source, projected in zip(deterministic_graph["links"], graph["links"], strict=True):
        projected["window"] = link_windows.get(source["id"], projected.get("window"))
    graph["edges"] = [{
        "pair": [candidate_keys[edge["from"]], candidate_keys[edge["to"]]],
        "link_key": link_keys[edge["link_id"]],
        "link_type": edge["link_type"], "style": edge["style"],
    } for edge in deterministic_graph["edges"]]
    # gaps are listed by hunt-scoped target and partition (link ids); order them by content
    canonical["coverage"]["gaps"].sort(key=lambda gap: json.dumps(gap, sort_keys=True, separators=(",", ":")))
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
            incident["timeline"], key=lambda item: (observed_at.get(item) is None, observed_at.get(item) or "", item),
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
            key=lambda item: (observed_at.get(item) is None, observed_at.get(item) or "", item),
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
