"""The AI triage order's report view, built from the stored pass for the manifest and the web page alike.

It is its own labelled section, after the deterministic findings: the promoted groups of each report section with
their assessment, incident label, rationale and cited findings, the findings each one moved (its shown excerpts; the
rest of the group keeps its deterministic place), and the pass's counts, reasons, usage and digest. It never reorders,
hides or relabels a deterministic finding. The view is stale when the hunt's deterministic order no longer matches the
pass's: the report verifies that with the export's own order digest.
"""
from __future__ import annotations

from romulus.agent.triage import LABEL, latest_failure
from romulus.agent.triage_order import SECTIONS_LANES, SECTIONS_RANKED, OrderWorkspace
from romulus.store.repo import TRIAGE_FAILED, TRIAGE_SUMMARY, Repo

FAILED_ACTION = TRIAGE_FAILED
SUMMARY_KEYS = ("status", "reason", "pass", "mode", "prompt_digest", "grouping", "model", "provider", "settings",
                "groups", "dropped", "calls", "usage", "findings")


def _stale(repo: Repo, hunt_id: str, summary: dict, verify_order: bool) -> bool:
    """Whether the stored pass no longer describes the hunt. Cheap checks first (finding count, final ranking); with
    `verify_order`, the deterministic order digest the export compares, staged as the pass staged it."""
    if summary.get("findings") != repo.reportable_count(hunt_id) or summary.get("rank_state") != repo.rank_state(
            hunt_id):
        return True
    if not verify_order:
        return False
    with OrderWorkspace(repo, hunt_id) as ws:
        ws.build()
        return ws.order_digest != summary.get("order_digest")


def triage_view(repo: Repo, hunt_id: str, *, verify_order: bool = True) -> dict | None:
    """The hunt's AI triage view, or None when no triage pass was ever attempted (the report is then unchanged)."""
    audit = repo.latest_audit(hunt_id, TRIAGE_SUMMARY)
    failure = latest_failure(repo, hunt_id)
    if audit is None and failure is None:
        return None
    summary = dict(audit["detail"]) if audit else {}
    titles = summary.get("sections") or list(SECTIONS_RANKED if summary.get("mode") == "ranked" else SECTIONS_LANES)
    view = {"label": LABEL, **{key: summary.get(key) for key in SUMMARY_KEYS}}
    if not audit:
        view.update(status="failed", reason=failure["reason"])
    view["stale"] = bool(audit) and _stale(repo, hunt_id, summary, verify_order)
    view["order_verified"] = bool(audit) and verify_order
    if audit and failure:
        view["last_attempt"] = failure
    sections = [{"section": index, "title": title, "promoted": []} for index, title in enumerate(titles)]
    after = 0
    while page := repo.triage_groups(hunt_id, statuses=("promoted",), after_position=after):
        for row in page:
            shown = list(row["finding_ids"] or [])
            sections[int(row["section"])]["promoted"].append({
                "group_id": row["group_id"], "position": row["position"], "best_position": row["best_position"],
                "rule_id": row["rule_id"], "entity": {"kind": row["entity_kind"], "value": row["entity"]},
                "finding_count": row["finding_count"], "case_findings": row["case_findings"],
                "finding_ids": shown, "moved": len(shown),
                "in_deterministic_place": max(0, int(row["finding_count"]) - len(shown)),
                "assessment": row["assessment"], "incident_label": row["incident_label"],
                "rationale": row["rationale"], "cites": list(row["cites"] or []),
            })
        after = page[-1]["position"]
    view["sections"] = sections
    return view
