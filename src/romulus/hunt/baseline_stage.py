"""Run the frozen-history baseline stage and publish cited deviation leads."""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from itertools import groupby

from romulus.baseline.carry import CarryInStore
from romulus.baseline.lookback import LookbackBudget, LookbackResult, LookbackWriter
from romulus.baseline.playbook import BASELINE_PLAYBOOKS, BaselinePlaybook
from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import BASELINE_SPECS, KeyContext
from romulus.decide.policy import decide
from romulus.detect import netdef
from romulus.detect.base import Match, PredicateField
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.evidence.typed import TypedEvent
from romulus.hunt.baseline_source import HuntHistorySource
from romulus.hunt.publish import publish_match
from romulus.sources.models import Window
from romulus.store.repo import Repo

BASELINE_CITATION_CAP = 20
_COMPLETE_WINDOW_STATES = {"evaluated_complete", "not_applicable_no_events"}
_PLAYBOOK_BY_SPEC = {playbook.spec.id: playbook for playbook in BASELINE_PLAYBOOKS}


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _task_id(hunt_id: str, manifest: dict) -> str:
    material = _canonical({"hunt_id": hunt_id, "baseline": manifest})
    return "baseline-" + hashlib.sha256(material.encode()).hexdigest()[:24]


def _coverage_failure(coverage: list[dict], minimum: int) -> str | None:
    if not coverage or all(item.get("status") == "absent" for item in coverage):
        return "no pre-window data"
    gaps = [gap for item in coverage for gap in item.get("gaps") or []]
    if gaps:
        reasons = "; ".join(sorted({str(gap.get("reason") or gap.get("state")) for gap in gaps}))
        return f"history gap: {reasons}"
    bad = [item for item in coverage if item.get("status") not in {"resolved", "shortened"}]
    if bad:
        shortest = min(int(item.get("effective_hours") or 0) for item in bad)
        return f"effective baseline span {shortest} hour(s) is below the required {minimum} live hours"
    return None


def _predicate(events: list[TypedEvent]) -> list[PredicateField]:
    """A bounded field-lineage witness for each cited first event."""
    out: list[PredicateField] = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        for name in sorted(event.fields):
            value = event.fields[name]
            identity = (name, value.origin)
            if value.origin and identity not in seen:
                out.append(PredicateField(name, value.value, value.origin))
                seen.add(identity)
                break
    return out


def _entities(events: list[TypedEvent]) -> list[tuple[str, str, str]]:
    return sorted({entity for event in events for entity in event.entities()})


class SnapshotView:
    """Streaming judge over one immutable snapshot and the sweep's persisted observations."""

    def __init__(self, repo: Repo, hunt_id: str, window: Window, snapshot: dict, *,
                 min_live_hours: int, networks_configured: bool):
        self.repo, self.hunt_id, self.window, self.snapshot = repo, hunt_id, window, snapshot
        self.min_live_hours, self.networks_configured = min_live_hours, networks_configured
        self.groups: dict[str, list[dict]] = {}
        self.spec_stats: dict[str, dict] = {}

    def _window_failure(self, playbook: BaselinePlaybook) -> str | None:
        cells = [cell for cell in self.repo.rule_cells(self.hunt_id, rule_id=playbook.id)
                 if cell["target"] != "*" and not cell["target"].startswith("baseline:")
                 and cell["state"] != "split"]
        if not cells:
            return "no baseline window cell was evaluated"
        partial = [cell for cell in cells if cell["state"] not in _COMPLETE_WINDOW_STATES]
        if partial:
            return f"window coverage is partial in {len(partial)} cell(s)"
        return None

    def _history_coverage(self, spec_id: str) -> list[dict]:
        coverage = self.snapshot.get("coverage") or {}
        wanted = {
            key.split("|", 1)[0] for key in coverage if key.endswith(f"|{spec_id}")
        }
        return [coverage[f"{target}|{spec_id}"] for target in sorted(wanted)
                if f"{target}|{spec_id}" in coverage]

    def _update_scope(self, playbook: BaselinePlaybook, rows: list[dict],
                      window_failure: str | None) -> tuple[list[dict], dict]:
        first = rows[0]
        series = self.repo.baseline_scope_series(
            first["scope_kind"], first["scope"], self.hunt_id, playbook.id,
        )
        # A frozen spec is only as complete as its least-complete target. Observations do not carry a source
        # target, and one scope can be split across targets, so narrowing coverage from history liveness could
        # turn another target's gap into a false first-seen claim.
        coverage = self._history_coverage(playbook.id)
        reason = None
        if playbook.id == "bl.ext_dest" and not self.networks_configured:
            reason = "internal networks not configured for this site; external destinations are unresolved"
        elif window_failure:
            reason = window_failure
        else:
            reason = _coverage_failure(coverage, self.min_live_hours)
        live_hours = len({item["hour"] for item in series})
        history_events = sum(int(item["events"]) for item in series)
        if reason is None and history_events < 1:
            reason = "scope is silent in history"
        if reason is None and live_hours < self.min_live_hours:
            reason = f"scope has {live_hours} live history hour(s), below the required {self.min_live_hours}"
        peers = (self.repo.baseline_peer_scopes(first["scope_kind"], self.hunt_id, playbook.id)
                 if playbook.spec.measure == "prevalence" else None)
        updated: list[dict] = []
        first_seen: list[dict] = []
        for source in rows:
            history = self.repo.baseline_key_history(
                source["key_id"], source["scope_kind"], source["scope"], self.hunt_id, playbook.id,
            )
            history_count = sum(int(item["count"]) for item in history)
            prevalence = (self.repo.baseline_key_prevalence(
                source["key_id"], source["scope_kind"], self.hunt_id, playbook.id,
            ) if peers is not None else None)
            verdict = "unresolved" if reason else "common" if history_count else "first_seen"
            item = {
                **source,
                "history_count": history_count,
                # Presence/common judgement has no decay. Rare is deliberately outside S5.
                "history_decayed": None,
                "peer_scopes_with_key": prevalence,
                "peer_scopes": peers,
                "threshold": None,
                "mean": None,
                "sigma": None,
                "n_hours": live_hours,
                "verdict": verdict,
                "reason": reason or (
                    f"absent from baseline {self.snapshot['digest']}" if verdict == "first_seen"
                    else f"present in baseline {self.snapshot['digest']}"
                ),
            }
            updated.append(item)
            if verdict == "first_seen":
                first_seen.append(item)
        effective_hours = min((int(item.get("effective_hours") or 0) for item in coverage), default=0)
        effective_start = max((str(item.get("effective_start")) for item in coverage), default=None)
        return first_seen, {
            "rows": updated, "coverage": coverage, "live_hours": live_hours,
            "history_events": history_events, "effective_hours": effective_hours,
            "effective_start": effective_start, "reason": reason,
        }

    def _claim(self, playbook: BaselinePlaybook, scope: str, first_seen: list[dict], facts: dict,
               cited: int) -> str:
        keys = "; ".join(
            f"{_canonical(row['key'])} (window count {row['window_count']}, history count 0)"
            for row in first_seen
        )
        peer_text = ""
        peer_total = first_seen[0].get("peer_scopes")
        if peer_total is not None and int(peer_total) >= 5:
            peer_text = "; peer prevalence " + ", ".join(
                f"{row['peer_scopes_with_key']}/{peer_total}" for row in first_seen
            )
        claim = (
            f"Between {self.window.start.isoformat()} and {self.window.end.isoformat()}, "
            f"{len(first_seen)} keys in {scope} were absent from baseline {self.snapshot['digest']}: {keys}. "
            f"The effective baseline spans {facts['effective_start']} to {self.window.start.isoformat()} "
            f"({facts['effective_hours']} hours), with {facts['live_hours']} live scope hours and "
            f"{facts['history_events']} scope events{peer_text}. "
        )
        if any(item.get("status") == "shortened" for item in facts["coverage"]):
            claim += "The complete baseline span was shortened by evidenced source absence. "
        exclusions = self.repo.baseline_snapshot_exclusions(self.hunt_id, playbook.id)
        if exclusions["segments"] and exclusions["hunted_segments"] == 0:
            claim += "The selected history was not itself hunted. "
        if exclusions["excluded_keys"]:
            claim += f"The selected baseline excluded {exclusions['excluded_keys']} cited key(s). "
        claim += (
            "This is a deviation: absence from a baseline is a deviation, not evidence of malicious activity. "
            f"The observation table retains all {len(first_seen)} keys; this lead cites the first event for "
            f"{cited} of them (citation cap {BASELINE_CITATION_CAP})."
        )
        return claim

    def judge(self, playbook: BaselinePlaybook) -> list[Match]:
        observations = self.repo.baseline_observations_for_spec(
            self.hunt_id, playbook.id, playbook.version,
        )
        matches: list[Match] = []
        updated_total = unresolved = common = first_total = 0
        window_failure = self._window_failure(playbook)
        spec_coverage = self._history_coverage(playbook.id)
        history_failure = _coverage_failure(spec_coverage, self.min_live_hours)
        if playbook.id == "bl.ext_dest" and not self.networks_configured:
            history_failure = "internal networks not configured for this site; external destinations are unresolved"
        for scope, grouped in groupby(observations, key=lambda row: row["scope"]):
            first_seen, facts = self._update_scope(playbook, list(grouped), window_failure)
            rows = facts["rows"]
            self.repo.upsert_baseline_observations(rows)
            updated_total += len(rows)
            unresolved += sum(row["verdict"] == "unresolved" for row in rows)
            common += sum(row["verdict"] == "common" for row in rows)
            first_total += len(first_seen)
            if not first_seen:
                continue
            ids = [row["first_event_id"] for row in first_seen[:BASELINE_CITATION_CAP]
                   if row.get("first_event_id")]
            stored = {row["id"]: TypedEvent.model_validate(row["event"])
                      for row in self.repo.events_by_ids(ids)}
            events = [stored[event_id] for event_id in ids if event_id in stored]
            if not events:
                for row in first_seen:
                    row.update(verdict="unresolved", reason="first citation event is not retained")
                self.repo.upsert_baseline_observations(first_seen)
                unresolved += len(first_seen)
                first_total -= len(first_seen)
                continue
            group_key = f"baseline:{playbook.id}:{scope}"
            self.groups[group_key] = first_seen
            matches.append(Match(
                playbook_id=playbook.id,
                claim=self._claim(playbook, scope, first_seen, facts, len(events)),
                claim_type="anomaly", events=events, predicate=_predicate(events),
                ts=min(event.ts for event in events), severity="info", proposed_lane="lead",
                confidence="medium", entities=_entities(events),
                notes=["baseline deviations are capped at the lead lane"], group_key=group_key,
            ))
        self.spec_stats[playbook.id] = {
            "observations": updated_total, "unresolved": unresolved,
            "common": common, "first_seen": first_total, "groups": len(matches),
            "window_failure": window_failure, "history_failure": history_failure,
        }
        return matches

    def attach_candidate(self, match: Match, candidate_id: str) -> None:
        rows = self.groups.get(match.group_key, ())
        self.repo.upsert_baseline_observations({**row, "candidate_id": candidate_id} for row in rows)


def _history_cell_state(coverage: dict) -> str:
    if coverage.get("status") in {"resolved", "shortened"}:
        return "complete"
    states = {gap.get("state") for gap in coverage.get("gaps") or []}
    if "failed" in states:
        return "failed"
    if "omitted_budget" in states:
        return "omitted_budget"
    return "partial"


def _write_history_cells(repo: Repo, hunt_id: str, snapshot: dict, specs: list,
                         owner_token: str | None) -> None:
    for target in snapshot["plan"]["targets"]:
        for spec in specs:
            coverage = snapshot["coverage"][f"{target}|{spec.id}"]
            repo.set_rule_cell(
                hunt_id, spec.id, spec.version, f"baseline:{target}", "history",
                _history_cell_state(coverage), 0, 0,
                {"snapshot_digest": snapshot["digest"], "coverage": coverage},
                owner_token=owner_token,
            )


def _write_rollup(repo: Repo, hunt_id: str, playbook: BaselinePlaybook, stats: dict,
                  snapshot: dict, owner_token: str | None) -> None:
    cells = [cell for cell in repo.rule_cells(hunt_id, rule_id=playbook.id)
             if cell["target"] != "*" and not cell["target"].startswith("baseline:")
             and cell["state"] != "split"]
    evaluated = sum(int(cell["evaluated"] or 0) for cell in cells)
    partial = bool(stats["unresolved"] or stats["window_failure"] or stats["history_failure"])
    if stats["groups"]:
        state = "match_on_partial" if partial else "matched"
    elif not playbook.assures_negative:
        state = "positive_only_partial" if partial else "positive_only"
    elif partial or not cells:
        state = "evaluated_partial"
    elif evaluated == 0:
        state = "not_applicable_no_events"
    else:
        state = "no_match_complete"
    reasons = []
    if stats["window_failure"]:
        reasons.append(stats["window_failure"])
    if stats["history_failure"]:
        reasons.append(stats["history_failure"])
    if stats["unresolved"]:
        reasons.append(f"{stats['unresolved']} unresolved scope key(s)")
    repo.set_rule_cell(
        hunt_id, playbook.id, playbook.version, "*", "window", state,
        stats["groups"], evaluated,
        {"reasons": reasons, "unresolved": stats["unresolved"], "snapshot_digest": snapshot["digest"]},
        owner_token=owner_token,
    )


def run_baseline_stage(repo: Repo, hunt_id: str, window: Window, *, client=None,
                       contracts: dict | None = None, source=None, heartbeat=lambda: None,
                       owner_token: str | None = None) -> dict:
    """Fill history once, freeze/reuse its cut, judge observations, and publish grouped leads."""
    hunt = repo.get_hunt(hunt_id)
    if hunt is None:
        raise KeyError(hunt_id)
    config = (hunt["manifest"].get("baseline") or {})
    wanted = {item["id"] for item in config.get("specs") or []}
    specs = [spec for spec in BASELINE_SPECS if spec.id in wanted and spec.id in _PLAYBOOK_BY_SPEC]
    if not specs:
        return {"finished": True, "status": "disabled", "snapshot_digest": None, "specs": {}}
    history_days = int(config.get("history_days", 7))
    min_live_hours = int(config.get("min_live_hours", 48))
    budget = config.get("budget") or {}
    task_id = _task_id(hunt_id, config)
    repo.upsert_task(task_id, hunt_id, "baseline", "baseline-stage", {
        "start": (window.start - timedelta(days=history_days)).isoformat(),
        "end": window.start.isoformat(), "specs": sorted(wanted),
    }, task_id, owner_token=owner_token)
    heartbeat()
    snapshot = repo.baseline_snapshot(hunt_id)
    result = LookbackResult(0, (), 0, 0, 0.0)
    if snapshot is None:
        history_source = source or HuntHistorySource(client, contracts or {})
        writer = LookbackWriter(
            repo, history_source, site=str(config["site"]), specs=specs,
            normalizer=NORMALIZER_VERSION,
            budget=LookbackBudget(
                queries=int(budget.get("queries", 200)), records=int(budget.get("records", 5_000_000)),
                seconds=float(budget.get("seconds", 1800)),
            ),
            context=KeyContext(is_internal=netdef.current().is_internal),
            parent_carry=CarryInStore(repo, hunt_id),
        )
        try:
            result = writer.fill(
                hunt_id=hunt_id, targets=list(hunt["manifest"]["targets"]),
                start=window.start - timedelta(days=history_days), end=window.start,
            )
        except Exception as exc:
            repo.update_task(task_id, "failed", error=str(exc)[:300], attempt=True,
                             owner_token=owner_token)
            raise
        repo.update_task(task_id, "executed", outcome={
            "complete": result.complete, "gaps": len(result.gaps),
            "queries": result.queries, "records": result.records,
        }, owner_token=owner_token)
        snapshot = SnapshotPlanner(repo).freeze(
            hunt_id=hunt_id, window_start=window.start, lookback=timedelta(days=history_days),
            min_live_hours=min_live_hours, site=str(config["site"]),
            targets=list(hunt["manifest"]["targets"]), specs=specs, history_gaps=result.gaps,
        )
    _write_history_cells(repo, hunt_id, snapshot, specs, owner_token)
    network_record = hunt["manifest"].get("internal_networks") or {}
    view = SnapshotView(
        repo, hunt_id, window, snapshot, min_live_hours=min_live_hours,
        networks_configured=network_record.get("source") == "configured",
    )
    for spec in specs:
        playbook = _PLAYBOOK_BY_SPEC[spec.id]()
        for match in playbook.judge(view):
            published = publish_match(
                repo, hunt_id, playbook, match, None, {}, owner_token=owner_token,
            )
            candidate_id = published["id"] if published is not None else decide(match, hunt_id).candidate_id
            if repo.candidate(candidate_id) is not None:
                view.attach_candidate(match, candidate_id)
        _write_rollup(repo, hunt_id, playbook, view.spec_stats[spec.id], snapshot, owner_token)
    status = ("partial" if any(item["unresolved"] or item["window_failure"] or item["history_failure"]
                               for item in view.spec_stats.values()) else "complete")
    summary = {
        "finished": True, "status": status, "snapshot_digest": snapshot["digest"],
        "snapshot_status": snapshot["status"], "specs": view.spec_stats,
        "lookback": {"complete": result.complete, "gaps": len(result.gaps),
                     "queries": result.queries, "records": result.records},
    }
    repo.update_task(task_id, "partial" if status == "partial" else "evaluated", outcome=summary,
                     owner_token=owner_token)
    return summary
