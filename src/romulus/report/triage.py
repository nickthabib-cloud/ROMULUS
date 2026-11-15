"""The AI triage order's report view, built from the stored pass for the manifest and the web page alike.

It is its own labelled section, after the deterministic findings: the promoted groups of each report section with
their assessment, incident label, rationale and cited findings, the findings each one moved (the excerpts it cited;
the rest of the group keeps its deterministic place, and a group that cited nothing moves nothing), and the pass's counts, reasons, usage and digest. It never reorders,
hides or relabels a deterministic finding. The view is stale when the hunt's deterministic order no longer matches the
pass's. The report checks that without staging anything: the finding count and final ranking first, then the order
digest of the findings the manifest already holds, ordered by the same key the pass staged them by (the export
re-stages the order). A check that cannot run leaves the view unverified; it never blocks the report.
"""
from __future__ import annotations

from romulus.agent.triage import LABEL, latest_failure
from romulus.agent.triage_order import (
    PLACEMENT_VERSION,
    SECTIONS_LANES,
    SECTIONS_RANKED,
    moved_ids,
    report_order_digest,
)
from romulus.hunt.rank import PASS_FINAL
from romulus.store.repo import TRIAGE_FAILED, TRIAGE_SUMMARY, Repo

FAILED_ACTION = TRIAGE_FAILED
SUMMARY_KEYS = ("status", "reason", "pass", "mode", "prompt_digest", "grouping", "model", "provider", "settings",
                "groups", "dropped", "calls", "usage", "findings")


def _stale(repo: Repo, hunt_id: str, summary: dict, findings: list[dict] | None) -> bool:
    """Whether the stored pass no longer describes the hunt: the finding count or final ranking changed, or (given
    the report's surfaced findings) their deterministic order digest differs from the pass's."""
    if summary.get("findings") != repo.reportable_count(hunt_id) or summary.get("rank_state") != repo.rank_state(
            hunt_id) or summary.get("placement") != PLACEMENT_VERSION:
        return True
    if findings is None:
        return False
    return report_order_digest(findings, repo.has_rank_pass(hunt_id, PASS_FINAL)) != summary.get("order_digest")


def triage_view(repo: Repo, hunt_id: str, *, findings: list[dict] | None = None) -> dict | None:
    """The hunt's AI triage view, or None when no triage pass was ever attempted (the report is then unchanged).
    `findings` are the report's surfaced findings, with their ranks: given them, the whole order is verified."""
    audit = repo.latest_audit(hunt_id, TRIAGE_SUMMARY)
    failure = latest_failure(repo, hunt_id)
    if audit is None and failure is None:
        return None
    summary = dict(audit["detail"]) if audit else {}
    titles = summary.get("sections") or list(SECTIONS_RANKED if summary.get("mode") == "ranked" else SECTIONS_LANES)
    view = {"label": LABEL, **{key: summary.get(key) for key in SUMMARY_KEYS}}
    if not audit:
        view.update(status="failed", reason=failure["reason"])
    view["order_verified"] = bool(audit) and findings is not None
    try:
        view["stale"] = bool(audit) and _stale(repo, hunt_id, summary, findings)
    except Exception as exc:  # noqa: BLE001 - the check is advisory: the view is shown unverified
        view.update(stale=None, order_verified=False, verification_error=f"{type(exc).__name__}: {exc}"[:300])
    if audit and failure:
        view["last_attempt"] = failure
    sections = [{"section": index, "title": title, "promoted": []} for index, title in enumerate(titles)]
    after = 0
    while page := repo.triage_groups(hunt_id, statuses=("promoted",), after_position=after):
        for row in page:
            shown = list(row["finding_ids"] or [])
            moved = moved_ids(shown, row["cites"])
            sections[int(row["section"])]["promoted"].append({
                "group_id": row["group_id"], "position": row["position"], "best_position": row["best_position"],
                "rule_id": row["rule_id"], "entity": {"kind": row["entity_kind"], "value": row["entity"]},
                "finding_count": row["finding_count"], "case_findings": row["case_findings"],
                "finding_ids": shown, "moved_ids": moved, "moved": len(moved), "nothing_cited": not moved,
                "in_deterministic_place": max(0, int(row["finding_count"]) - len(moved)),
                "assessment": row["assessment"], "incident_label": row["incident_label"],
                "rationale": row["rationale"], "cites": list(row["cites"] or []),
            })
        after = page[-1]["position"]
    view["sections"] = sections
    return view
