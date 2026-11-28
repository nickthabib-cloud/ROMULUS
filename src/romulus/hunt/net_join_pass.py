"""The network-to-host join's pass after the packet and baseline stages, over the rows the sweep kept.

The sweep joins the administration sessions its own findings cite (`romulus.detect.net_host_join`) and keeps the join's
compact rows in the hunt's stage directory. Once the packet and baseline stages have published their findings (the
first-seen administration pair among them), this pass joins the sessions those findings cite against the same rows,
and revises, never duplicates, the item of a (destination host, client address, service) it already published. Its
tables record what each pass judged and published, so running it again (a resume) adds nothing twice. A later stage
that runs again on resume reopens the pass first, and the pass runs again after it. The rows are removed when a pass
finishes after both later stages finished, when the hunt is deleted, and by the pruning at the next hunt's start
(hunts that no longer exist, or whose pass finished with no later stage left to run again). Rows that are missing leave the later stages' sessions unresolved, named; the
sweep is never run again to rebuild them.
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from romulus.detect.net_host_join import (
    LIMIT_PREFIX,
    NETWORK_FAMILIES,
    NOTE_PREFIX,
    AdminSession,
    NetworkAdminLogonJoin,
    admin_session,
)
from romulus.evidence.typed import TypedEvent
from romulus.hunt.publish import SourceCitationFetcher, publish_match
from romulus.store.repo import Repo

log = logging.getLogger(__name__)

JOIN_DIR = "join"
SUMMARY_ACTION = "hunt.join_summary"
ROWS_MISSING = ("join rows not available on resume (the sweep's kept rows are missing: an older hunt, rows the stage "
                "volume had no room for, or rows deleted)")


def rows_path(stage_dir, hunt_id: str) -> Path:
    """Where the sweep keeps one hunt's join rows (a hunt id is one plain name: it never leaves the folder)."""
    if not hunt_id or not all(char.isalnum() or char in "-_" for char in hunt_id):
        raise ValueError(f"not a hunt id: {hunt_id!r}")
    return Path(stage_dir) / JOIN_DIR / f"{hunt_id}.db"


def discard_rows(stage_dir, hunt_id: str) -> None:
    """Remove one hunt's kept join rows (and any half-written copy)."""
    path = rows_path(stage_dir, hunt_id)
    for item in (path, path.with_name(path.name + ".part")):
        item.unlink(missing_ok=True)


def prune_rows(stage_dir, repo: Repo) -> int:
    """Remove kept join rows of hunts that no longer exist or whose later pass finished; returns how many."""
    folder = Path(stage_dir) / JOIN_DIR
    if not folder.is_dir():
        return 0
    removed = 0
    for path in sorted(folder.glob("*.db")):
        hunt_id = path.stem
        try:
            rows_path(stage_dir, hunt_id)
        except ValueError:
            continue                                    # not a file the sweep wrote
        if repo.get_hunt(hunt_id) is None or (finished(repo, hunt_id) and not _kept_for_resume(repo, hunt_id)):
            discard_rows(stage_dir, hunt_id)
            removed += 1
    return removed


def finished(repo: Repo, hunt_id: str) -> bool:
    return bool(((repo.latest_audit(hunt_id, SUMMARY_ACTION) or {}).get("detail") or {}).get("finished"))


def _kept_for_resume(repo: Repo, hunt_id: str) -> bool:
    return bool(((repo.latest_audit(hunt_id, SUMMARY_ACTION) or {}).get("detail") or {}).get("rows_kept_for_resume"))


class _KeptRows:
    """The kept rows as the join reads and writes them (`.db`, `.write`)."""

    def __init__(self, path: Path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=MEMORY")

    def write(self, sql: str, rows: list[tuple]) -> None:
        self.db.executemany(sql, rows)
        self.db.commit()

    def close(self) -> None:
        self.db.close()


def _later_rules() -> frozenset[str]:
    from romulus.baseline.playbook import BASELINE_PLAYBOOKS
    from romulus.detect.packets import PACKET_PLAYBOOKS
    return frozenset(rule.id for rule in [*BASELINE_PLAYBOOKS, *PACKET_PLAYBOOKS])


def run_join_pass(repo: Repo, client, hunt_id: str, stage_dir, *, owner_token: str | None = None,
                  heartbeat=None, keep_rows: bool = False) -> dict:
    """Join the sessions the packet and baseline stages' findings cite, publish or revise the items, restate the
    rule's window cell, and record the pass's summary. `keep_rows`: a later stage has not finished, so a resume runs
    it again and this pass after it; the kept rows stay for that pass (the summary says so, and pruning keeps them)."""
    rule = NetworkAdminLogonJoin()
    rule.citation_fetcher = SourceCitationFetcher(client)
    rule.later_rules = _later_rules()
    if heartbeat is not None:
        rule.heartbeat = heartbeat
    rule.bind_published(
        lambda lane, offset, limit: repo.candidate_page(hunt_id, offset=offset, limit=limit, lane=lane),
        lambda ids: [TypedEvent.model_validate(row["event"]) for row in repo.citation_events(hunt_id, list(ids))])
    path = rows_path(stage_dir, hunt_id)
    published = 0
    if path.is_file():
        rows = _KeptRows(path)
        try:
            for match in rule.join_pass(rows, later=True):
                publish_match(repo, hunt_id, rule, match, None, {}, owner_token=owner_token)
                published += 1
            notes = rule.summary_notes(rows)
            matched = rows.db.execute("SELECT count(DISTINCT gkey) FROM res").fetchone()[0]
        finally:
            rows.close()
        _restate_cell(repo, hunt_id, rule, notes, matched, partial=False, owner_token=owner_token)
        summary = {"finished": True, "complete": not rule.partial_notes(notes), "rows": "kept",
                   "items_published_or_revised": published, "notes": notes}
    else:
        missing = _unjoinable_sessions(rule, repo, hunt_id)
        notes = [NOTE_PREFIX + f"{missing} administration session(s) cited by packet- or baseline-stage findings left "
                               f"unresolved (never a negative): {ROWS_MISSING}"] if missing else []
        _restate_cell(repo, hunt_id, rule, notes, None, partial=bool(missing), owner_token=owner_token)
        summary = {"finished": True, "complete": not missing, "rows": "missing", "unresolved_sessions": missing,
                   "notes": notes}
    if keep_rows and path.is_file():
        summary["rows_kept_for_resume"] = True
    repo.audit("system", SUMMARY_ACTION, hunt_id, summary, owner_token=owner_token)
    if not summary.get("rows_kept_for_resume"):
        discard_rows(stage_dir, hunt_id)
    return summary


def reopen(repo: Repo, hunt_id: str, stage: str, *, owner_token: str | None = None) -> None:
    """A later stage is about to run again, and it may publish findings whose sessions the finished pass never saw.
    Record, before it runs, that the pass is unfinished (so a crash in between still leaves it to a resume) and make
    the join's window cell partial until the pass runs again."""
    if not finished(repo, hunt_id):
        return
    reason = f"the {stage} runs again; the pass runs again after it"
    repo.audit("system", SUMMARY_ACTION, hunt_id, {"finished": False, "complete": False, "reopened": reason},
               owner_token=owner_token)
    mark_not_run(repo, hunt_id, reason, owner_token=owner_token)


def mark_not_run(repo: Repo, hunt_id: str, reason: str, *, owner_token: str | None = None) -> None:
    """The pass did not run (a stop) or did not finish (an error): the join's window cell is partial and says so until
    a resume runs it."""
    rule = NetworkAdminLogonJoin()
    note = (NOTE_PREFIX + f"the pass over the packet and baseline stages' findings did not finish ({reason}); "
                          "their sessions are not yet joined")
    _restate_cell(repo, hunt_id, rule, [note], None, partial=True, owner_token=owner_token)


def _unjoinable_sessions(rule: NetworkAdminLogonJoin, repo: Repo, hunt_id: str) -> int:
    """Without the kept rows: the distinct administration connections the later stages' findings cite."""
    connections, ids = set(), []
    for lane in ("urgent", "high", "lead"):
        offset = 0
        while True:
            page = repo.candidate_page(hunt_id, offset=offset, limit=rule.FINDING_PAGE, lane=lane)
            if not page:
                break
            offset += len(page)
            ids += [str(eid) for row in page if row["rule_id"] in rule.later_rules
                    and row.get("provenance", "deterministic") == "deterministic"
                    for eid in row.get("event_ids") or []]
    for start in range(0, len(ids), rule.EVENT_BATCH):
        for row in repo.citation_events(hunt_id, ids[start:start + rule.EVENT_BATCH]):
            event = TypedEvent.model_validate(row["event"])
            session = admin_session(event) if event.family in NETWORK_FAMILIES else None
            if isinstance(session, AdminSession):
                connections.add((session.client, session.cport, session.server, session.sport))
    return len(connections)


def _restate_cell(repo: Repo, hunt_id: str, rule: NetworkAdminLogonJoin, notes: list[str], matched: int | None, *,
                  partial: bool, owner_token: str | None) -> None:
    """The rule's whole-window cell with the join's statements replaced by this pass's (every other reason kept)."""
    cell = next((item for item in repo.rule_cells(hunt_id, rule_id=rule.id)
                 if item["target"] == "*" and item["partition"] == "window"), None)
    detail = dict((cell or {}).get("detail") or {})
    # the join's own statements are restated whole; every other reason (its state limits, the rollup) is kept, and a
    # restated limit identical to one kept appears once
    kept = [reason for reason in detail.get("reasons") or [] if not reason.startswith(NOTE_PREFIX)]
    reasons = [*kept, *[("state limit: " + note[len(LIMIT_PREFIX):]) if note.startswith(LIMIT_PREFIX) else note
                        for note in notes]]
    state = (cell or {}).get("state") or "positive_only_partial"
    # partial only for a reason the cell names: a reason kept from the sweep (its rollup, a state limit, an
    # assumed direction) or one of this pass's; a statement this pass replaced leaves no partial behind
    partial = partial or bool(kept) or rule.partial_notes(notes) or state == "executed_failed"
    if state == "executed_failed":
        new_state = state
    elif matched is None:
        matched = (cell or {}).get("matched") or 0
        new_state = "match_on_partial" if matched and partial else "matched" if matched else (
            "positive_only_partial" if partial else "positive_only")
    else:
        new_state = ("match_on_partial" if partial else "matched") if matched else (
            "positive_only_partial" if partial else "positive_only")
    repo.set_rule_cell(hunt_id, rule.id, rule.version, "*", "window", new_state, matched or 0,
                       (cell or {}).get("evaluated") or 0, {**detail, "reasons": list(dict.fromkeys(reasons))},
                       owner_token=owner_token)
