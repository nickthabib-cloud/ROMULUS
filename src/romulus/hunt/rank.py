"""Evidence-ranking passes over a hunt's stored candidates, and the expansion seeds they choose.

Pass 1 runs after the sweep, packet and baseline stages and chooses expansion's seeds. Pass 2 runs after expansion
and its context pass; reports, the web and the agent dossier read it. Each pass is computed in bounded keyset pages
over the store (`romulus.store.ranks`) and replaces the hunt's previous rows for that pass atomically, so running a
pass again over the same stored candidates (a resumed hunt) gives the same ranks.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime

from romulus.decide import rank as model
from romulus.detect.metadata import finding_attack, hunt_rule_metadata
from romulus.detect.netdef import SiteNetworks
from romulus.store.ranks import parse_time, stored_time
from romulus.store.repo import Repo, is_lease_lost

log = logging.getLogger("romulus.rank")

PASS_BEFORE_EXPANSION = 1
PASS_FINAL = 2
SUMMARY_ACTIONS = {PASS_BEFORE_EXPANSION: "hunt.rank_pass_1_summary", PASS_FINAL: "hunt.rank_pass_2_summary"}
# Rows a pass holds in Python at once (one keyset page). A few thousand rows of a few hundred bytes are a few MB on
# any host; a larger page only saves round trips, and per-entity state lives in the store's staging tables.
RANK_BATCH = 2000


def _window(manifest: dict) -> tuple[datetime, datetime]:
    window = manifest.get("window") or {}
    return parse_time(window["start"]), parse_time(window["end"])


def _json_list(value) -> str:
    return json.dumps(list(value), ensure_ascii=False)


def compute_rank_pass(repo: Repo, hunt_id: str, pass_no: int, *, owner_token: str | None = None,
                      batch_size: int = RANK_BATCH, heartbeat: Callable[[], None] = lambda: None) -> dict:
    """Compute one ranking pass and publish it; return its summary."""
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    manifest = hunt["manifest"] or {}
    start, end = _window(manifest)
    window_seconds = (end - start).total_seconds()
    rules = hunt_rule_metadata(repo, manifest=manifest)
    is_internal = model.address_is_internal(SiteNetworks.from_record(manifest.get("internal_networks")))
    # (rule, explicit techniques) -> counted tactics; bounded by the rule catalog and its technique lists
    tactics_of: dict[tuple, tuple[str, ...]] = {}

    def tactics(rule_id: str, attack: list) -> tuple[str, ...]:
        key = (rule_id, tuple(str(item) for item in attack))
        if key not in tactics_of:
            tactics_of[key] = tuple(sorted(set(finding_attack(list(key[1]), rules.get(rule_id), groups=True)[1])))
        return tactics_of[key]

    with repo.rank_workspace(hunt_id, pass_no) as ws:
        # Addresses one host's own telemetry owns, so a network endpoint and that host are one entity.
        ws.stage_addresses(start, end, model.NETWORK_FAMILIES)
        ws.commit()
        pages = _stage_population(ws, batch_size, heartbeat, is_internal, tactics)
        ws.stage_fleet_hosts()
        hunt_hosts = ws.hunt_hosts()
        fleet: dict[str, str] = {}
        fleet_rules = []
        for rule_id, hosts, first, last in ws.rule_spread():
            span = (last - first).total_seconds() if first is not None and last is not None else 0.0
            if model.fleet_recurring(hosts, hunt_hosts, span, window_seconds):
                fleet[rule_id] = model.fleet_reason(rule_id, hosts, hunt_hosts, span, window_seconds)
                fleet_rules.append({"rule_id": rule_id, "hosts": hosts, "span_seconds": span})
        ws.mark_fleet(fleet)
        ws.aggregate_entities()
        ws.commit()
        _cooccurrence(ws, batch_size, heartbeat)
        _score_entities(ws, batch_size, heartbeat)
        _rank_findings(ws, batch_size, heartbeat)
        counts = ws.counts()
        ws.publish(owner_token)
        return {
            "pass": pass_no, "version": model.RANK_VERSION, "status": "complete", "hunt_hosts": hunt_hosts,
            "window_seconds": window_seconds, "fleet_recurring_rules": fleet_rules, **counts,
            "batch_size": batch_size, "population_pages": pages, "peak_rows": ws.peak_rows, "queries": ws.queries,
        }


def _stage_population(ws, batch_size: int, heartbeat, is_internal, tactics) -> int:
    after, pages = "", 0
    while True:
        page = ws.population_page(after, batch_size)
        if not page:
            return pages
        pages += 1
        heartbeat()
        wanted = {address for row in page
                  for address in model.finding_addresses(row["entities"], is_internal=is_internal)}
        hosts = ws.addresses(wanted)
        findings, members, tactic_rows, rule_hosts, hunt_hosts = [], [], [], [], []
        for row in page:
            # Findings the AI agent proposed, and the legacy investigator's case discoveries, are ranked but never
            # counted toward any entity's evidence or any rule's prevalence.
            deterministic = row["provenance"] != model.AGENT_PROVENANCE and row["source_case_id"] is None
            entities = model.ranking_entities(row["entities"], is_internal=is_internal, host_for_address=hosts)
            ranked = row["lane"] in model.RANKED_LANES
            if deterministic:
                found_on = [value for kind, value in entities if kind == model.HOST]
                hunt_hosts.extend({"host": value} for value in found_on)
                if ranked:
                    # a rule's prevalence counts only its reportable instances: context and suppressed records of
                    # the same rule never make its attack instances look like fleet noise
                    rule_hosts.extend({"rule_id": row["rule_id"], "host": value} for value in found_on)
            if not ranked:
                continue
            ts = stored_time(row["ts"])
            findings.append({"candidate_id": row["id"], "rule_id": row["rule_id"], "ts": ts, "lane": row["lane"],
                             "prior": float(row["priority"]),
                             "provenance": (row["provenance"] if row["source_case_id"] is None
                                            or row["provenance"] == model.AGENT_PROVENANCE
                                            else model.CASE_PROVENANCE)})
            counted = tactics(row["rule_id"], row["attack"]) if deterministic else ()
            for kind, value in entities:
                members.append({"entity_kind": kind, "entity": value, "candidate_id": row["id"],
                                "rule_id": row["rule_id"], "ts": ts,
                                "confirmed": int(row["lane"] == model.CONFIRMED_LANE),
                                "contributes": int(deterministic), "prior": float(row["priority"])})
                tactic_rows.extend({"entity_kind": kind, "entity": value, "rule_id": row["rule_id"],
                                    "tactic": tactic} for tactic in counted)
        ws.stage(findings, members, tactic_rows, rule_hosts, hunt_hosts)
        ws.commit()
        after = page[-1]["id"]


def _cooccurrence(ws, batch_size: int, heartbeat) -> None:
    """One time-ordered scan per entity with a bounded window of rules (`CooccurrenceScan`)."""
    current, scan, updates = None, None, []
    after = None

    def flush():
        if current is not None and scan.count:
            updates.append({"entity_kind": current[0], "entity": current[1], "cooccur": scan.count})

    while True:
        page = ws.timeline_page(after, batch_size)
        if not page:
            break
        heartbeat()
        for row in page:
            key = (row["entity_kind"], row["entity"])
            if key != current:
                flush()
                current, scan = key, model.CooccurrenceScan()
            if not scan.full:       # past the cap, the rest of this entity's rows add nothing
                scan.add(row["rule_id"], parse_time(row["ts"]))
        last = page[-1]
        after = (last["entity_kind"], last["entity"], last["ts"], last["rule_id"], last["candidate_id"])
        if len(updates) >= batch_size:
            ws.set_cooccurrence(updates)
            updates = []
    flush()
    ws.set_cooccurrence(updates)
    ws.commit()


def _pairs(ws, batch_size: int):
    """Every entity's matching pairs, in entity order, one keyset page at a time."""
    after = None
    while True:
        page = ws.pair_page(after, batch_size)
        if not page:
            return
        yield from page
        last = page[-1]
        after = (last["entity_kind"], last["entity"], last["rule_id"], last["tactic"])


def _score_entities(ws, batch_size: int, heartbeat) -> None:
    """Score entities in pages, merging the matching pairs stream (same entity order) so that only one entity's
    pairs (at most MATCHING_RULES_PER_TACTIC per tactic) are held besides the two pages."""
    ws.stage_matching_pairs(model.MATCHING_RULES_PER_TACTIC)
    ws.commit()
    pairs = _pairs(ws, batch_size)
    pending = next(pairs, None)
    after = None
    while True:
        page = ws.entity_page(after, batch_size)
        if not page:
            break
        heartbeat()
        rows = []
        for item in page:
            key = (item["entity_kind"], item["entity"])
            rule_tactics: dict[str, set[str]] = defaultdict(set)
            while pending is not None and (pending["entity_kind"], pending["entity"]) <= key:
                if (pending["entity_kind"], pending["entity"]) == key:
                    rule_tactics[pending["rule_id"]].add(pending["tactic"])
                pending = next(pairs, None)
            seen = {tactic for tactics in rule_tactics.values() for tactic in tactics}
            notes = (() if len(seen) <= model.MATCHING_RULES_PER_TACTIC else (
                (f"tactic breadth may be understated: {len(seen)} tactics exceed the "
                 f"{model.MATCHING_RULES_PER_TACTIC} rules kept per tactic"),))
            matched = model.tactic_breadth(rule_tactics)
            score, reported, reasons = model.entity_score(model.EntityEvidence(
                confirmed=int(item["confirmed"]), tactics=matched, rules=int(item["rules"]),
                cooccurrence=int(item["cooccur"]), max_prior=item["max_prior"], fleet_rules=item["fleet_rules"],
                notes=notes))
            if len(seen) > len(matched):
                reasons.insert(2, "tactics seen on the entity: " + ", ".join(sorted(seen)))
            rows.append({"entity_kind": item["entity_kind"], "entity": item["entity"], "score": score,
                         "reported": int(reported), "reasons": _json_list(reasons),
                         "tactics": _json_list(matched)})
        ws.set_entity_scores(rows)
        ws.commit()
        after = (page[-1]["entity_kind"], page[-1]["entity"])


def _rank_findings(ws, batch_size: int, heartbeat) -> None:
    after = ""
    while True:
        page = ws.finding_page(after, batch_size)
        if not page:
            break
        heartbeat()
        by_finding: dict[str, list[model.EntityRank]] = defaultdict(list)
        for pair in ws.finding_entities(page[0]["candidate_id"], page[-1]["candidate_id"]):
            by_finding[pair["candidate_id"]].append(model.EntityRank(
                pair["entity_kind"], pair["entity"], float(pair["score"]), bool(pair["reported"])))
        rows = []
        for item in page:
            score, best, reported, reasons = model.finding_rank(
                lane=item["lane"], prior=float(item["prior"]), provenance=item["provenance"],
                entities=by_finding.get(item["candidate_id"], []), fleet=item["fleet"])
            rows.append({"candidate_id": item["candidate_id"], "score": score, "reported": int(reported),
                         "entity_kind": best.kind if best else model.UNATTRIBUTED,
                         "entity": best.value if best else None, "reasons": _json_list(reasons)})
        ws.set_finding_ranks(rows)
        ws.commit()
        after = page[-1]["candidate_id"]


def run_rank_pass(repo: Repo, hunt_id: str, pass_no: int, *, owner_token: str | None = None,
                  heartbeat: Callable[[], None] = lambda: None) -> dict:
    """Run a pass and record its summary. A failed pass never stops the hunt: its rows are removed (so no stale
    ranks are shown), the failure is recorded, and the hunt falls back to the rule estimate (lanes)."""
    try:
        summary = compute_rank_pass(repo, hunt_id, pass_no, owner_token=owner_token, heartbeat=heartbeat)
    except Exception as exc:
        if is_lease_lost(exc):
            raise
        log.exception("ranking pass %s failed", pass_no)
        summary = {"pass": pass_no, "version": model.RANK_VERSION, "status": "failed",
                   "reason": f"ranking error: {type(exc).__name__}: {exc}"[:300]}
        try:
            repo.delete_rank_pass(hunt_id, pass_no, owner_token=owner_token)
        except Exception as cleanup:
            if is_lease_lost(cleanup):
                raise
            log.exception("could not remove the failed ranking pass")
    repo.audit("system", SUMMARY_ACTIONS[pass_no], hunt_id, summary, owner_token=owner_token)
    return summary


def rank_summary(repo: Repo, hunt_id: str, pass_no: int = PASS_FINAL) -> dict | None:
    audit = repo.latest_audit(hunt_id, SUMMARY_ACTIONS[pass_no])
    return dict(audit["detail"]) if audit else None


# Expansion reads the pass-1 Reported set (repo.finding_ranks_page, reported only) to choose its extra seeds.


# -- findings added after the last pass ------------------------------------------------------------------------------
def rank_unranked(repo: Repo, hunt_id: str, candidates: list[dict], *, pass_no: int = PASS_FINAL) -> dict[str, dict]:
    """Ranks for pool findings stored after the pass ran (an AI agent's proposals), from the pass's stored entity
    scores. Such findings never change an entity's evidence, so the entity scores stand. An internal endpoint is
    resolved by its address here (the pass's address map is not stored)."""
    if not candidates:
        return {}
    hunt = repo.get_hunt(hunt_id) or {}
    is_internal = model.address_is_internal(SiteNetworks.from_record(
        (hunt.get("manifest") or {}).get("internal_networks")))
    keyed = {row["id"]: model.ranking_entities(row.get("entities") or [], is_internal=is_internal)
             for row in candidates}
    stored = repo.entity_ranks_for(hunt_id, pass_no, {key for keys in keyed.values() for key in keys})
    fleet = {item["rule_id"]: item for item in (rank_summary(repo, hunt_id, pass_no) or {}).get(
        "fleet_recurring_rules") or []}
    out = {}
    for row in candidates:
        entities = [model.EntityRank(kind, value, float(stored[(kind, value)]["score"]),
                                     bool(stored[(kind, value)]["reported"]))
                    for kind, value in keyed[row["id"]] if (kind, value) in stored]
        reason = None
        if row["rule_id"] in fleet:
            reason = f"recurring fleet-wide rule {row['rule_id']} (-{model.FLEET_PENALTY})"
        score, best, reported, reasons = model.finding_rank(
            lane=row["lane"], prior=float(row["priority"]),
            provenance=(model.CASE_PROVENANCE if row.get("source_case_id") is not None
                        and row.get("provenance") != model.AGENT_PROVENANCE
                        else row.get("provenance", "deterministic")),
            entities=entities, fleet=reason)
        out[row["id"]] = {"score": score, "position": None, "reported": reported,
                          "entity_kind": best.kind if best else model.UNATTRIBUTED,
                          "entity": best.value if best else None,
                          "reasons": [*reasons, "ranked from the stored entity scores after the last ranking pass"]}
    return out
