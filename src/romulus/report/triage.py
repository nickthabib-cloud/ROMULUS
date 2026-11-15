"""The AI triage order's report view, built from the stored pass for the manifest and the web page alike.

It is its own labelled section, after the deterministic findings: the promoted groups of each report section with
their assessment, incident label, rationale and cited findings, and the pass's counts, reasons, usage and digest. It
never reorders, hides or relabels a deterministic finding. A view whose stored findings or final ranking changed
after the pass is marked stale.
"""
from __future__ import annotations

from romulus.agent.triage import LABEL
from romulus.agent.triage_order import SECTIONS_LANES, SECTIONS_RANKED
from romulus.store.repo import TRIAGE_SUMMARY, Repo

FAILED_ACTION = TRIAGE_SUMMARY + "_failed"
SUMMARY_KEYS = ("status", "reason", "pass", "mode", "prompt_digest", "grouping", "model", "provider", "settings",
                "groups", "dropped", "calls", "usage", "findings")


def triage_view(repo: Repo, hunt_id: str) -> dict | None:
    """The hunt's AI triage view, or None when no triage pass was ever attempted (the report is then unchanged)."""
    audit = repo.latest_audit(hunt_id, TRIAGE_SUMMARY)
    failed = repo.latest_audit(hunt_id, FAILED_ACTION)
    if audit is None and failed is None:
        return None
    summary = dict(audit["detail"]) if audit else {}
    titles = summary.get("sections") or list(SECTIONS_RANKED if summary.get("mode") == "ranked" else SECTIONS_LANES)
    view = {"label": LABEL, **{key: summary.get(key) for key in SUMMARY_KEYS}}
    if not audit:
        view.update(status="failed", reason=(failed["detail"] or {}).get("reason"))
    view["stale"] = bool(audit) and (summary.get("findings") != repo.reportable_count(hunt_id)
                                     or summary.get("rank_state") != repo.rank_state(hunt_id))
    if audit and failed and failed["id"] > audit["id"]:
        view["last_attempt"] = {"status": "failed", "reason": (failed["detail"] or {}).get("reason")}
    sections = [{"section": index, "title": title, "promoted": []} for index, title in enumerate(titles)]
    after = 0
    while page := repo.triage_groups(hunt_id, statuses=("promoted",), after_position=after):
        for row in page:
            sections[int(row["section"])]["promoted"].append({
                "group_id": row["group_id"], "position": row["position"], "best_position": row["best_position"],
                "rule_id": row["rule_id"], "entity": {"kind": row["entity_kind"], "value": row["entity"]},
                "finding_count": row["finding_count"], "finding_ids": list(row["finding_ids"] or []),
                "assessment": row["assessment"], "incident_label": row["incident_label"],
                "rationale": row["rationale"], "cites": list(row["cites"] or []),
            })
        after = page[-1]["position"]
    view["sections"] = sections
    return view
