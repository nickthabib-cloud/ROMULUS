"""PROTOCOL §10 miss funnel: the furthest stage each missed observable opportunity reached.

Stages: source -> queried -> retrieved -> normalized -> evaluated -> candidate -> surfaced_only -> reported.

The hunt store keeps only candidate-supporting records, so 'retrieved' is inferred from a complete covering
sweep task, and 'normalized'/'evaluated' are determined by replaying the product normalizer (the version the
hunt recorded) over the gold records, fetched read-only from the source. Without a fetcher those two stages
are 'undetermined' and the funnel stops at 'retrieved'.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from eval.gold import Gold, locator_key, parse_ts
from eval.hunt import Hunt, case_entity_values
from eval.match import ItemMatch, ok_roles

STAGES = ("source", "queried", "retrieved", "normalized", "evaluated", "candidate", "surfaced_only", "reported")
REPLAY_CAP = 3000          # gold records replayed per (opportunity, source); bounded, documented
SOURCE_KINDS = {"host_index": "es", "network_index": "es", "arkime": "arkime", "pcap": "pcap"}


def _task_covers(task: dict, index: str, ts, dataset: str | None) -> bool:
    it = task.get("intent") or {}
    if it.get("target") != index or task.get("state") == "split":
        return False
    w = it.get("window") or {}
    t0, t1 = parse_ts(w.get("start")), parse_ts(w.get("end"))
    if not (t0 and t1 and ts and t0 <= ts < t1):
        return False
    for f in it.get("filters") or []:
        if f.get("field") == "event.dataset" and dataset:
            vals = f.get("value")
            vals = vals if isinstance(vals, list) else [vals]
            if f.get("op") in ("in", "eq", "==") and dataset not in vals:
                return False
    return True


def _complete(task: dict) -> bool:
    o = task.get("outcome") or {}
    return task.get("state") in ("evaluated", "ingested") and o.get("completeness") == "complete"


def _cell_evaluated(hunt: Hunt, rule_id: str, target: str, ts) -> bool:
    for c in hunt.rule_cells:
        if c["rule_id"] != rule_id or c["target"] != target or c["state"] in ("planned", "executed_failed", "split"):
            continue
        if "/" not in c["partition"] or not (c.get("evaluated") or 0):
            continue
        p0, p1 = c["partition"].split("/", 1)
        a, b = parse_ts(p0), parse_ts(p1)
        if a and b and a <= ts < b:
            return True
    return False


def compute(gold: Gold, hunt: Hunt, matches: list[ItemMatch], hits: dict,
            fetcher: Callable[[str, list[str]], list[dict]] | None = None,
            normalize: Callable | None = None) -> dict:
    pack = (hunt.manifest.get("pack") or {}).get("playbooks", [])
    fam_rules: dict[str, list[str]] = {}
    for p in pack:
        for f in p.get("families", []):
            fam_rules.setdefault(f, []).append(p["id"])
    targeted = {str((t.get("intent") or {}).get("target", "")) for t in hunt.tasks}
    loc_candidates: set[str] = set()
    for m in matches:
        loc_candidates |= m.tier_a | {oid for oid, _ in m.anomalies}
    per_opp = {}
    notes = Counter()
    replay_used = fetcher is not None and normalize is not None
    for oid, opp in gold.opportunities.items():
        if opp.observability != "observable":
            continue
        if oid in hits["reported"]:
            per_opp[oid] = {"stage": "reported"}
            continue
        best = "source"
        per_src = {}
        for src, status in opp.source_status.items():
            if status != "direct":
                continue
            stage = "source"
            kind = SOURCE_KINDS[src]
            if kind != "es":
                if not any(t.startswith(kind) for t in targeted):
                    notes[f"{src}: no task targets this source"] += 1
                per_src[src] = stage
                best = max(best, stage, key=STAGES.index)
                continue
            rows = [r for r in gold.es_rows.get((oid, src), []) if r[1] in ok_roles(opp)]
            queried = [r for r in rows if any(_task_covers(t, r[0][1], r[2], r[3]) for t in hunt.tasks)]
            if queried:
                stage = "queried"
                retrieved = [r for r in queried if any(_task_covers(t, r[0][1], r[2], r[3]) and _complete(t)
                                                        for t in hunt.tasks)]
                if retrieved:
                    stage = "retrieved"
                    if replay_used:
                        sample = sorted(retrieved, key=lambda r: (r[2], r[0][2]))[:REPLAY_CAP]
                        by_index: dict[str, list[str]] = {}
                        for r in sample:
                            by_index.setdefault(r[0][1], []).append(r[0][2])
                        hits_src = []
                        for idx, ids in by_index.items():
                            hits_src += fetcher(idx, ids)
                        events, _skips, _errs = normalize(hits_src)
                        keys = {r[0] for r in sample}
                        mine = [e for e in events
                                if any(locator_key("es", ref.target, ref.native_id) in keys for ref in e.raw)]
                        if mine:
                            stage = "normalized"
                            if any(_cell_evaluated(hunt, rid, ref.target, e.ts)
                                   for e in mine for rid in fam_rules.get(e.family, []) for ref in e.raw[:1]):
                                stage = "evaluated"
                    else:
                        notes["normalizer replay not run: normalized/evaluated undetermined"] += 1
            per_src[src] = stage
            best = max(best, stage, key=STAGES.index)
        if oid in loc_candidates:
            best = max(best, "candidate", key=STAGES.index)
        if oid in hits["surfaced"]:
            best = "surfaced_only"
        agent = any(case_entity_values(c.get("entities")) & gold.expand(opp.entities) for c in hunt.cases)
        per_opp[oid] = {"stage": best, "per_source": per_src, "agent_touched": agent,
                        "mentioned": oid in hits["mentioned"]}
    by_stage_class = Counter()
    by_stage = Counter()
    for oid, r in per_opp.items():
        if r["stage"] == "reported":
            continue
        by_stage[r["stage"]] += 1
        by_stage_class[(r["stage"], gold.opportunities[oid].behavior_class)] += 1
    return {"replay": f"product normalizer replay over gold records (cap {REPLAY_CAP} per opportunity/source)"
            if replay_used else "not run", "by_stage": {s: by_stage.get(s, 0) for s in STAGES if s != "reported"},
            "by_stage_class": {f"{s}|{c}": n for (s, c), n in sorted(by_stage_class.items())},
            "misses": sum(by_stage.values()), "notes": dict(notes),
            "_per_opp": per_opp}
