"""Score one hunt against a gold inventory and write an aggregate result (PROTOCOL §6–§10).

Usage (on the VM, from the deployed app directory):
    python -m eval.score --gold DIR --db PATH --hunt ID --run-id ID --out-md FILE [--out-json FILE]
        [--private-out FILE] [--adjudications FILE] [--es-env FILE] [--mode dev|holdout] [--note TEXT ...]

The hunt DB is opened read-only. Per-opportunity output (--private-out) is refused inside the repo.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from eval import agent as agent_mod
from eval import funnel as funnel_mod
from eval import gold as gold_mod
from eval import metrics as M
from eval.hunt import SURFACED_LANES, connect_ro, load_hunt
from eval.match import match_all
from eval.report import dumps, leak_check, render

REPO_ROOT = Path(__file__).resolve().parent.parent


def _commit() -> str:
    stamp = REPO_ROOT / "DEPLOYED_COMMIT"
    if stamp.exists():
        return stamp.read_text().strip()
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _inside_repo(p: Path) -> bool:
    try:
        p.resolve().relative_to(REPO_ROOT)
        return True
    except ValueError:
        return False


def score(gold_dir, db_path, hunt_id, run_id, mode="dev", adjudications=None, fetcher=None, normalize=None,
          notes=None) -> tuple[dict, dict, gold_mod.Gold]:
    g = gold_mod.load(gold_dir)
    conn = connect_ro(db_path)
    try:
        h = load_hunt(conn, hunt_id)
    finally:
        conn.close()
    matches = match_all(h.items, g)
    hits = M.hit_sets(matches)
    rec = M.recall(g, hits)
    adj = M.load_adjudications(adjudications)
    ordered, basis = M.review_list(h, matches)
    rows = M.classify(ordered, adj)
    source_check = None
    if fetcher is not None:
        from romulus.evidence.normalize import raw_digest
        source_check = {}
        rep_keys = {c["key"]: c["digest"] for m in matches if m.item.lane in M.REPORTED_LANES for c in m.item.locators
                    if c["key"] and c["key"][0] == "es"}
        by_index: dict[str, list[str]] = {}
        for k in rep_keys:
            by_index.setdefault(k[1], []).append(k[2])
        found = {}
        for idx, ids in by_index.items():
            for hit in fetcher(idx, ids):
                found[("es", hit["_index"], hit["_id"])] = raw_digest(hit["_source"])
        source_check = {k: found.get(k) == d for k, d in rep_keys.items()}
    fun = funnel_mod.compute(g, h, matches, hits, fetcher=fetcher, normalize=normalize)
    agent_eff, agent_private = agent_mod.effectiveness(h, g, matches, hits, adj)
    agent = next((a["detail"] for a in reversed(h.audit) if a["action"] == "hunt.agent_summary"), None) or {}
    model_off = not h.model_calls and agent.get("status") in ("disabled", None, "unknown")
    hm = h.manifest
    gaps = list(h.gaps)
    gaps += [("typed_event and raw_record rows are not hunt-scoped (a typed event keeps the hunt_id of the first "
             "hunt that stored it; raw_record has no hunt id), and only candidate-supporting records are retained: "
             "per-hunt retrieval and normalization of a given record cannot be read from the store; the funnel infers "
             "'retrieved' from complete covering tasks and replays the normalizer"),
             "no per-request ES accounting (request count, bytes) and no per-task duration beyond created/updated",
             ("candidates carry one timestamp; the item time range is rebuilt from cited typed events (EVE flow.start/"
             "flow.end where present)"),
             "context-lane items exist only in the hunt DB, not in the report manifest (I10); scoring reads the DB"]
    if not any(str((t.get("intent") or {}).get("target", "")).startswith(("arkime", "pcap")) for t in h.tasks):
        gaps.append("no Arkime or PCAP tasks exist (adapters not built): those sources stop at 'source' in the funnel")
    ver_note = None
    if normalize is not None:
        from romulus.evidence.normalize import NORMALIZER_VERSION
        if hm.get("normalizer") != NORMALIZER_VERSION:
            ver_note = (f"normalizer replay used {NORMALIZER_VERSION} but the hunt recorded {hm.get('normalizer')}; "
                        "normalized/evaluated stages are approximate")
    result = {
        "schema": "eval-result/1", "run_id": run_id, "dataset": g.dataset, "mode": mode,
        "scored_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gold": {"version": g.version, "files_sha256": g.files_sha256},
        "scorer": {"commit": _commit(), "matching_rule": "PROTOCOL §6 (2026-10-19)"},
        "hunt": {"id": h.id, "execution_state": h.execution_state, "detection_result": h.detection_result,
                 "window": f"{(hm.get('window') or {}).get('start')} → {(hm.get('window') or {}).get('end')}",
                 "pack": (hm.get("pack") or {}).get("version"), "normalizer": hm.get("normalizer"),
                 "policy": hm.get("policy"), "model": hm.get("model"), "config_digest": hm.get("config_digest"),
                 "manifest_digest": next((a["detail"].get("digest") for a in h.audit
                                          if a["action"] == "hunt.create" and a.get("detail")), None),
                 "model_off": model_off, "agent_status": agent.get("status", "unknown")},
        "recall": rec,
        "matching": {"items_by_lane": _count(m.item.lane for m in matches),
                     "tier_a_items_by_lane": _count(m.item.lane for m in matches if m.tier_a),
                     "tier_b_only_opps": sum(1 for oid, o in g.opportunities.items() if o.observability == "observable"
                                             and oid not in hits["surfaced"]
                                             and any(oid in m.tier_b for m in matches if m.item.lane in SURFACED_LANES)),
                     "anomalies": sum(len(m.anomalies) for m in matches)},
        "precision": {"order_basis": basis, "surfaced_total": len(rows), "p10": M.precision_at(rows, 10),
                      "p20": M.precision_at(rows, 20)},
        "false_leads": M.false_leads(rows),
        "citations": M.citation_validity(matches, source_check),
        "timing": M.timing(h, g, matches), "cost": M.cost(h),
        "coverage_claims": M.coverage_claims(h, g),
        "funnel": {k: v for k, v in fun.items() if not k.startswith("_")},
        "agent": agent_eff,
        "comparisons": {"Model-on vs model-off": "see the ablation file when both runs exist", "Simple baseline (§8.1)": "pending",
                        "AMiner alerts (§8.2)": "pending", "Telosian alerts (§8.2)": "pending"},
        "data_gaps": gaps, "notes": list(notes or []) + ([ver_note] if ver_note else []),
    }
    if mode == "holdout":
        result["funnel"].pop("by_stage_class", None)
        for k in ("reported", "surfaced"):
            result["recall"][k].pop("by_class", None)
    private = {"run_id": run_id, "hunt": h.id,
               "per_opportunity": {oid: {"reported": oid in hits["reported"], "surfaced": oid in hits["surfaced"],
                                         "mentioned": oid in hits["mentioned"],
                                         "sources_hit": sorted(hits["surfaced"].get(oid, set())),
                                         "funnel": fun["_per_opp"].get(oid)} for oid in g.opportunities},
               "anomalies": [{"item_id": m.item.id, "rule_id": m.item.rule_id, "lane": m.item.lane, "opp": o, "why": w}
                             for m in matches for o, w in m.anomalies],
               "agent": agent_private,
               "review": rows,
               "unadjudicated": [{"signature": r["signature"], "item_id": r["item_id"], "rule_id": r["rule_id"],
                                  "lane": r["lane"]} for r in rows if r["tp"] is None]}
    return result, private, g


def _count(it) -> dict:
    out: dict = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return dict(sorted(out.items()))


def write_outputs(result: dict, private: dict, forbidden: set[str], out_md=None, out_json=None, private_out=None):
    md, js = render(result), dumps(result)
    leak_check(md, forbidden)
    leak_check(js, forbidden)
    if out_md:
        Path(out_md).write_text(md, encoding="utf-8", newline="\n")
    if out_json:
        Path(out_json).write_text(js + "\n", encoding="utf-8", newline="\n")
    if private_out:
        p = Path(private_out)
        if _inside_repo(p):
            raise PermissionError("per-opportunity output must not be written inside the repo")
        p.write_text(json.dumps(private, indent=1, default=str), encoding="utf-8")
        p.chmod(0o600)
    return md


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="eval.score", description=__doc__.splitlines()[0])
    ap.add_argument("--gold", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--hunt", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--mode", choices=("dev", "holdout"), default="dev")
    ap.add_argument("--adjudications")
    ap.add_argument("--es-env", help="env file with ES_URL/ES_USERNAME/ES_PASSWORD (read-only use)")
    ap.add_argument("--out-md")
    ap.add_argument("--out-json")
    ap.add_argument("--private-out")
    ap.add_argument("--note", action="append", default=[])
    a = ap.parse_args(argv)
    fetcher = normalize = None
    if a.es_env:
        from eval.esfetch import make_fetcher
        from romulus.evidence.normalize import normalize_hits
        fetcher, normalize = make_fetcher(a.es_env), normalize_hits
    result, private, g = score(a.gold, a.db, a.hunt, a.run_id, a.mode, a.adjudications, fetcher, normalize, a.note)
    md = write_outputs(result, private, g.forbidden_strings(), a.out_md, a.out_json, a.private_out)
    if not a.out_md:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
