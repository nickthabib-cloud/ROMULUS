"""Run the frozen-history baseline stage and publish cited deviation leads."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import datetime, timedelta
from itertools import groupby

from romulus.baseline.carry import CarryInStore, PendingResolver
from romulus.baseline.count import KeyCounter
from romulus.baseline.lookback import LookbackBudget, LookbackResult, LookbackWriter
from romulus.baseline.playbook import BASELINE_PLAYBOOKS, BaselinePlaybook
from romulus.baseline.rate import RATE_MEAN_MULTIPLIER, RATE_MIN_COUNT, RATE_SIGMA_MULTIPLIER, threshold
from romulus.baseline.snapshot import SnapshotPlanner
from romulus.baseline.spec import BASELINE_SPECS, SPEC_BY_ID, KeyContext, Pending
from romulus.decide.policy import decide
from romulus.detect import netdef
from romulus.detect.base import Match, PredicateField
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.evidence.typed import TypedEvent
from romulus.hunt.baseline_source import HuntHistorySource
from romulus.hunt.publish import publish_match
from romulus.hunt.sweep import baseline_applicability
from romulus.sources.models import Window
from romulus.store.repo import Repo

BASELINE_CITATION_CAP = 20
_HOUR = timedelta(hours=1)
_COMPLETE_WINDOW_STATES = {"evaluated_complete", "not_applicable_no_events"}
_PLAYBOOK_BY_SPEC = {playbook.spec.id: playbook for playbook in BASELINE_PLAYBOOKS}


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _task_id(hunt_id: str, manifest: dict) -> str:
    material = _canonical({"hunt_id": hunt_id, "baseline": manifest})
    return "baseline-" + hashlib.sha256(material.encode()).hexdigest()[:24]


def _coverage_failure(coverage: list[dict], minimum: int) -> str | None:
    coverage = [item for item in coverage if item.get("status") != "not_applicable"]
    if not coverage:
        return None
    gaps = [gap for item in coverage for gap in item.get("gaps") or []]
    if all(item.get("status") == "absent" for item in coverage):
        # The hours read are complete and empty; absence is evidenced only where nothing was left unread. Hours the
        # lookback budget never reached are not evidence that the source holds nothing there.
        # every target's read stopped at or after the earliest end of its unread hours, so nothing before it was read
        unread = [gap["end"] for gap in gaps if gap.get("state") == "omitted_budget" and gap.get("end")]
        if unread:
            return (f"no pre-window data in the hours read; history not read before {min(unread)}: lookback "
                    f"budget exhausted")
        if gaps:
            reasons = "; ".join(sorted({str(gap.get("reason") or gap.get("state")) for gap in gaps}))
            return f"no pre-window data in the hours read; history gap: {reasons}"
        return "no pre-window data"
    if gaps:
        reasons = "; ".join(sorted({str(gap.get("reason") or gap.get("state")) for gap in gaps}))
        return f"history gap: {reasons}"
    bad = [item for item in coverage if item.get("status") not in {"resolved", "shortened"}]
    if bad:
        shortest = min(int(item.get("effective_hours") or 0) for item in bad)
        return f"effective baseline span {shortest} hour(s) is below the required {minimum} live hours"
    return None


def _predicate(events: list[TypedEvent], playbook: BaselinePlaybook) -> list[PredicateField]:
    """A bounded field-lineage witness for the typed fields that define the baseline key."""
    out: list[PredicateField] = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        for requirement in playbook.spec.required_fields.get(event.family, ()):
            names = requirement if isinstance(requirement, tuple) else (requirement,)
            name = next((candidate for candidate in names if event.has(candidate)), None)
            if name is None:
                continue
            value = event.fields[name]
            identity = (name, value.origin)
            if value.origin and identity not in seen:
                out.append(PredicateField(name, value.value, value.origin))
                seen.add(identity)
    return out


def _entities(events: list[TypedEvent]) -> list[tuple[str, str, str]]:
    return sorted({entity for event in events for entity in event.entities()})


def _pending_observation(hunt_id: str, spec, row: dict) -> dict:
    return {
        "hunt_id": hunt_id, "spec_id": spec.id, "spec_version": spec.version, **row,
        "history_count": None, "history_decayed": None, "peer_scopes_with_key": None,
        "peer_scopes": None, "threshold": None, "mean": None, "sigma": None,
        "n_hours": None, "verdict": "unresolved", "reason": "baseline judgement pending",
        "candidate_id": None,
    }


def resolve_window_exec_pairs(repo: Repo, hunt_id: str, window: Window) -> None:
    """Resolve durable compact window Pendings after lookback has filled the parent carry."""
    spec = SPEC_BY_ID["bl.exec_pair"]
    cells = repo.baseline_window_cells(hunt_id)
    carry_root = CarryInStore(repo, hunt_id)
    for target in sorted({row["target"] for row in cells}):
        target_cells = [row for row in cells if row["target"] == target]
        carry = carry_root.for_target(target, horizon=window.end)
        for cell in target_cells:
            rows = repo.baseline_window_execs(hunt_id, target, cell["partition"])
            carry.observe_window_rows(rows, hour=(cell["start"], cell["end"]))
            uncarried, hostless = carry.take_uncarried()
            carry.record_breaks(uncarried)
            if cell["source_complete"] and not hostless:
                carry.mark_observed(cell["start"], cell["end"])
        resolver = PendingResolver(carry, spec)
        for cell in target_cells:
            if repo.baseline_window_cell_done(
                    hunt_id, spec.id, spec.version, target, cell["partition"]):
                repo.drop_baseline_window_cell(hunt_id, target, cell["partition"])
                continue
            reasons = list(cell["reasons"])
            segment_counter = KeyCounter(
                cell["partition"], spec, span=(cell["start"], cell["end"]),
                retain_observations_when_partial=True,
            )
            segment_counter.restore(
                repo.baseline_window_counts(
                    hunt_id, spec.id, target, partition=cell["partition"],
                ),
                repo.baseline_window_scope_hours(
                    hunt_id, spec.id, target, partition=cell["partition"],
                ),
            )
            pending_counter = KeyCounter(
                cell["partition"], spec, span=(cell["start"], cell["end"]),
                retain_observations_when_partial=True,
            )
            for body in repo.baseline_window_pendings(hunt_id, target, cell["partition"]):
                pending = Pending(**body)
                resolution = resolver.resolve(pending)
                if resolution.reason is not None:
                    reasons.append(f"{pending.event_id}: {resolution.reason}")
                    segment_counter.mark_partial(reasons[-1])
                    pending_counter.mark_partial(reasons[-1])
                else:
                    refs = [{"target": source, "native_id": native}
                            for source, native in pending.raw_refs]
                    segment_counter.add_keys(
                        pending.ts, resolution.keys, event_id=pending.event_id, event_refs=refs,
                    )
                    pending_counter.add_keys(
                        pending.ts, resolution.keys, event_id=pending.event_id, event_refs=refs,
                    )
            observations = [
                *repo.baseline_window_observations(hunt_id, target, cell["partition"]),
                *pending_counter.observation_rows(),
            ]
            execs = [row for row in repo.baseline_window_execs(hunt_id, target, cell["partition"])
                     if row.get("family", "process_exec") == "process_exec"]
            state = (
                "not_applicable_no_events" if not cell["target_applicable"] else
                "not_applicable_no_events" if not execs and cell["source_complete"] else
                "evaluated_partial" if reasons or not cell["source_complete"] else
                "evaluated_complete"
            )
            repo.save_baseline_window_cell(hunt_id, {
                "rule_id": spec.id, "version": spec.version, "target": target,
                "partition": cell["partition"], "state": state, "matched": 0,
                "evaluated": cell["evaluated"], "detail": {"reasons": sorted(set(reasons))},
            }, (_pending_observation(hunt_id, spec, row) for row in observations),
                counts=segment_counter.material_count_rows(), scope_hours=segment_counter.scope_hour_rows(),
                event_hours=repo.baseline_window_event_hours(
                    hunt_id, spec.id, target, partition=cell["partition"],
                ))
            repo.drop_baseline_window_cell(hunt_id, target, cell["partition"])


class SnapshotView:
    """Streaming judge over one immutable snapshot and the sweep's persisted observations."""

    def __init__(self, repo: Repo, hunt_id: str, window: Window, snapshot: dict, *,
                 min_live_hours: int, networks_configured: bool, citation_source=None):
        self.repo, self.hunt_id, self.window, self.snapshot = repo, hunt_id, window, snapshot
        self.min_live_hours, self.networks_configured = min_live_hours, networks_configured
        self.citation_source = citation_source
        plan = snapshot.get("plan") or {}
        # Member segments may straddle history_start; only their rows inside the frozen span are history.
        self.span = ((datetime.fromisoformat(plan["history_start"]), datetime.fromisoformat(plan["window_start"]))
                     if plan.get("history_start") and plan.get("window_start") else None)
        hunt = repo.get_hunt(hunt_id) or {}
        rate_config = ((((hunt.get("manifest") or {}).get("baseline") or {}).get("thresholds") or {})
                       .get("rate") or {})
        self.rate_parameters = {
            "min_count": float(rate_config.get("min_count", RATE_MIN_COUNT)),
            "k": float(rate_config.get("k", RATE_MEAN_MULTIPLIER)),
            "z": float(rate_config.get("z", RATE_SIGMA_MULTIPLIER)),
        }
        self._pending_group: tuple[str, list[dict]] | None = None
        self.spec_stats: dict[str, dict] = {}

    def _window_failure(self, playbook: BaselinePlaybook) -> str | None:
        cells = [cell for cell in self.repo.rule_cells(self.hunt_id, rule_id=playbook.id)
                 if not (cell["target"] == "*" and cell["partition"] == "window")
                 and not cell["target"].startswith("baseline:")
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
                if f"{target}|{spec_id}" in coverage
                and coverage[f"{target}|{spec_id}"].get("status") != "not_applicable"]

    def _update_scope(self, playbook: BaselinePlaybook, rows: list[dict],
                      window_failure: str | None) -> tuple[list[dict], dict]:
        first = rows[0]
        series = self.repo.baseline_scope_series(
            first["scope_kind"], first["scope"], self.hunt_id, playbook.id, self.span,
        )
        # A frozen spec is only as complete as its least-complete target. Observations do not carry a source
        # target, and one scope can be split across targets, so narrowing coverage from history liveness could
        # turn another target's gap into a false first-seen claim.
        coverage = self._history_coverage(playbook.id)
        reason = None
        if playbook.id == "bl.ext_dest" and not self.networks_configured:
            reason = "internal networks not configured for this site; external destinations are unresolved"
        else:
            reason = _coverage_failure(coverage, self.min_live_hours)
        live: set[datetime] = set()
        history_events = 0
        for item in series:
            live.add(item["hour"])
            history_events += int(item["events"])
        live_hours = len(live)
        if reason is None and history_events < 1:
            reason = "scope is silent in history"
        if reason is None and live_hours < self.min_live_hours:
            reason = f"scope has {live_hours} live history hour(s), below the required {self.min_live_hours}"
        peers = (self.repo.baseline_peer_scopes(first["scope_kind"], self.hunt_id, playbook.id, self.span)
                 if playbook.spec.measure == "prevalence" else None)
        updated: list[dict] = []
        first_seen: list[dict] = []
        for source in rows:
            history = self.repo.baseline_key_history(
                source["key_id"], source["scope_kind"], source["scope"], self.hunt_id, playbook.id, self.span,
            )
            history_count = sum(int(item["count"]) for item in history)
            prevalence = (self.repo.baseline_key_prevalence(
                source["key_id"], source["scope_kind"], self.hunt_id, playbook.id, self.span,
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
        history_count_upper_bound = bool(
            playbook.spec.bucket == "day" and self.span is not None
            and self.span[0] != self.span[0].replace(hour=0, minute=0, second=0, microsecond=0)
        )
        return first_seen, {
            "rows": updated, "coverage": coverage, "live_hours": live_hours,
            "history_events": history_events, "effective_hours": effective_hours,
            "effective_start": effective_start, "reason": reason,
            "history_count_upper_bound": history_count_upper_bound,
        }

    def _whole_window(self) -> tuple[datetime, datetime, list[tuple[datetime, datetime]]]:
        start_floor = self.window.start.replace(minute=0, second=0, microsecond=0)
        end_floor = self.window.end.replace(minute=0, second=0, microsecond=0)
        whole_start = start_floor if self.window.start == start_floor else start_floor + _HOUR
        whole_end = end_floor
        edges = []
        if self.window.start < min(whole_start, self.window.end):
            edges.append((self.window.start, min(whole_start, self.window.end)))
        if max(whole_end, self.window.start) < self.window.end:
            tail = (max(whole_end, self.window.start), self.window.end)
            if not edges or edges[-1] != tail:
                edges.append(tail)
        return whole_start, whole_end, edges

    @staticmethod
    def _edge_text(edges: list[tuple[datetime, datetime]]) -> str:
        if not edges:
            return ""
        spans = ", ".join(f"{start.isoformat()} to {end.isoformat()}" for start, end in edges)
        return f" The window edge fractions {spans} were not assessed."

    def _rate_scope(self, playbook: BaselinePlaybook, rows: list[dict],
                    window_failure: str | None) -> tuple[list[dict], list[dict], dict]:
        first = rows[0]
        coverage = self._history_coverage(playbook.id)
        reason = _coverage_failure(coverage, self.min_live_hours)
        plan = self.snapshot.get("plan") or {}
        history_end = datetime.fromisoformat(plan.get("window_start") or self.window.start.isoformat())
        starts = [datetime.fromisoformat(str(item["effective_start"])) for item in coverage
                  if item.get("effective_start")]
        history_start = max(starts) if starts else history_end
        sparse: dict[datetime, int] = {}
        for item in self.repo.baseline_scope_series(
                first["scope_kind"], first["scope"], self.hunt_id, playbook.id,
                (history_start, history_end)):
            sparse[item["hour"]] = sparse.get(item["hour"], 0) + int(item["events"])
        host = None
        if first["scope"].startswith("host_account:"):
            try:
                body = json.loads(first["scope"].removeprefix("host_account:"))
                host = body.get("host") if isinstance(body, dict) else None
            except (TypeError, ValueError):
                pass
        live = (sorted(set(self.repo.baseline_host_hours(
            host, self.hunt_id, (history_start, history_end),
        ))) if isinstance(host, str) and host else [])
        history_events = sum(sparse.get(hour, 0) for hour in live)
        n_hours = len(live)
        if reason is None and not live:
            reason = "host liveness is unavailable"
        if reason is None and n_hours < self.min_live_hours:
            reason = f"fewer than {self.min_live_hours} live history hours"
        if reason is None and history_events < 1:
            reason = "scope is silent in history"
        series = [sparse.get(hour, 0) for hour in live]
        statistics = None
        if reason is None:
            statistics = threshold(series, **self.rate_parameters)

        whole_start, whole_end, edges = self._whole_window()
        if reason is None and whole_start >= whole_end:
            reason = "window has no complete whole hour"
        measurements = (list(self.repo.baseline_window_scope_series(
            self.hunt_id, playbook.id, first["scope_kind"], first["scope"],
            span=(whole_start, whole_end),
        )) if whole_start < whole_end else [])
        partial_cells = [cell for cell in self.repo.rule_cells(self.hunt_id, rule_id=playbook.id)
                         if not (cell["target"] == "*" and cell["partition"] == "window")
                         and not cell["target"].startswith("baseline:")
                         and cell["state"] != "split" and cell["state"] not in _COMPLETE_WINDOW_STATES]
        partial_hours = {
            datetime.fromisoformat(value)
            for cell in partial_cells
            for value in (cell.get("detail") or {}).get("partial_hours") or []
        }
        whole_cell_partial = any(
            (cell.get("detail") or {}).get("whole_cell_partial")
            or not (cell.get("detail") or {}).get("partial_hours")
            for cell in partial_cells
        )
        if whole_cell_partial:
            measurements = []
        elif partial_hours:
            measurements = [item for item in measurements if item["hour"] not in partial_hours]
        anomalous = ([] if reason or statistics is None else [
            item for item in measurements if int(item["events"]) >= statistics.value
        ])
        if reason is None and window_failure and not anomalous:
            reason = window_failure
        verdict = "unresolved" if reason else "over_threshold" if anomalous else "within_threshold"
        edge_text = self._edge_text(edges)
        if reason:
            verdict_reason = reason + edge_text
        elif anomalous:
            verdict_reason = (f"{len(anomalous)} complete window hour(s) met or exceeded threshold "
                              f"{statistics.value}{edge_text}")
            if window_failure:
                verdict_reason += f"; other window cells were partial ({window_failure})"
        else:
            verdict_reason = f"no complete window hour met threshold {statistics.value}{edge_text}"
        updated = [{
            **row,
            "history_count": history_events,
            "history_decayed": None,
            "peer_scopes_with_key": None,
            "peer_scopes": None,
            "threshold": None if statistics is None else statistics.value,
            "mean": None if statistics is None else statistics.mean,
            "sigma": None if statistics is None else statistics.sigma,
            "n_hours": n_hours,
            "verdict": verdict,
            "reason": verdict_reason,
        } for row in rows]
        return updated, anomalous, {
            "coverage": coverage, "history_start": history_start, "history_end": history_end,
            "history_events": history_events, "statistics": statistics, "edges": edges,
            "window_failure": window_failure,
        }

    def _rate_claim(self, playbook: BaselinePlaybook, scope: str, cited_hours: list[dict], facts: dict,
                    total_anomalous: int, unlisted: int, missing_witnesses: int) -> str:
        statistics = facts["statistics"]
        assert statistics is not None
        hours = "; ".join(
            f"{item['hour'].isoformat()} count {int(item['events'])}" for item in cited_hours
        )
        if unlisted:
            hours += f"; and {unlisted} more hours (in the observation table)"
        claim = (
            f"Between {self.window.start.isoformat()} and {self.window.end.isoformat()}, {scope} met or "
            f"exceeded its service-account execution-rate threshold in {total_anomalous} complete hour(s): "
            f"{hours}. The threshold was {statistics.value} = max(min_count {statistics.min_count:g}, "
            f"mean × k ({statistics.mean} × {statistics.k:g}), mean + z × sample sigma "
            f"({statistics.mean} + {statistics.z:g} × {statistics.sigma})); n={statistics.n}. The exact "
            f"history series spans {facts['history_start'].isoformat()} to {facts['history_end'].isoformat()} "
            f"and contains {facts['history_events']} executions; rate-series decay is none. Seasonality is "
            "not modelled."
        )
        claim += self._edge_text(facts["edges"])
        if facts.get("window_failure"):
            claim += f" Other window cells were partial ({facts['window_failure']})."
        if missing_witnesses:
            claim += f" There were {missing_witnesses} anomalous hour(s) whose witness could not be retained."
        claim += (
            f" Baseline {self.snapshot['digest']} supplied the frozen history. This rate deviation is not "
            f"evidence of malicious activity. The lead cites one retained event from each of the {len(cited_hours)} "
            "anomalous hour(s)."
        )
        return claim

    def _judge_rate(self, playbook: BaselinePlaybook) -> Iterator[Match]:
        observations = self.repo.baseline_observations_for_spec(
            self.hunt_id, playbook.id, playbook.spec.version,
        )
        updated_total = unresolved = over = within = groups = 0
        window_failure = self._window_failure(playbook)
        coverage = self._history_coverage(playbook.id)
        history_failure = _coverage_failure(coverage, self.min_live_hours)
        for scope, grouped in groupby(observations, key=lambda row: row["scope"]):
            rows, anomalous, facts = self._rate_scope(playbook, list(grouped), window_failure)
            self.repo.upsert_baseline_observations(rows)
            updated_total += len(rows)
            unresolved += sum(row["verdict"] == "unresolved" for row in rows)
            over += sum(row["verdict"] == "over_threshold" for row in rows)
            within += sum(row["verdict"] == "within_threshold" for row in rows)
            if not anomalous:
                continue
            shown = anomalous[:BASELINE_CITATION_CAP]
            witnesses = [{
                "first_event_id": item.get("first_event_id"),
                "first_event_refs": item.get("first_event_refs") or [],
            } for item in shown]
            events, raw_copies = self._citation_events(witnesses)
            retained_ids = {event.id for event in events}
            cited_hours = [item for item in shown if item.get("first_event_id") in retained_ids]
            missing_witnesses = len(shown) - len(cited_hours)
            if not cited_hours:
                for row in rows:
                    row.update(verdict="unresolved", reason="no anomalous hour has a retained citation event")
                self.repo.upsert_baseline_observations(rows)
                unresolved += len(rows)
                over -= len(rows)
                continue
            group_key = f"baseline:{playbook.id}:{scope}"
            self._pending_group = (group_key, rows)
            groups += 1
            yield Match(
                playbook_id=playbook.id,
                claim=self._rate_claim(
                    playbook, scope, cited_hours, facts, len(anomalous), len(anomalous) - len(shown),
                    missing_witnesses,
                ),
                claim_type="anomaly", events=events, predicate=_predicate(events, playbook),
                ts=min(event.ts for event in events), severity="info", proposed_lane="lead",
                confidence="medium", entities=_entities(events),
                notes=["baseline rate deviations are capped at the lead lane"], group_key=group_key,
                raw_copies=raw_copies,
            )
        self.spec_stats[playbook.id] = {
            "observations": updated_total, "unresolved": unresolved,
            "common": 0, "first_seen": 0, "over_threshold": over, "within_threshold": within,
            "groups": groups, "window_failure": window_failure, "history_failure": history_failure,
        }

    def _claim(self, playbook: BaselinePlaybook, scope: str, first_seen: list[dict], facts: dict,
               cited: int) -> str:
        shown = first_seen[:BASELINE_CITATION_CAP]
        history_label = "history count at most 0" if facts.get("history_count_upper_bound") else "history count 0"
        keys = "; ".join(
            f"{_canonical(row['key'])} (window count {row['window_count']}, {history_label})"
            for row in shown
        )
        remaining = len(first_seen) - len(shown)
        if remaining:
            keys += f"; and {remaining} more keys (in the observation table)"
        peer_text = ""
        peer_total = first_seen[0].get("peer_scopes")
        if peer_total is not None and int(peer_total) >= 5:
            peer_text = "; peer prevalence " + ", ".join(
                f"{row['peer_scopes_with_key']}/{peer_total}" for row in shown
            )
            if remaining:
                peer_text += f", and {remaining} more"
        noun = "key" if len(first_seen) == 1 else "keys"
        claim = (
            f"Between {self.window.start.isoformat()} and {self.window.end.isoformat()}, "
            f"{len(first_seen)} {noun} in {scope} {'was' if len(first_seen) == 1 else 'were'} absent from "
            f"baseline {self.snapshot['digest']}: {keys}. "
            f"The effective baseline spans {facts['effective_start']} to {self.window.start.isoformat()} "
            f"({facts['effective_hours']} hours), with {facts['live_hours']} live scope hours and "
            f"{facts['history_events']} scope events{peer_text}. "
        )
        if playbook.id == "bl.cmd_shape":
            claim += (
                "The argv masking replaces variable IP addresses, numbers, UUIDs, long hexadecimal values, "
                "mktemp-style random names, and base64 blobs with class tokens; chmod permission modes remain "
                "literal. "
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

    def _citation_events(self, rows: list[dict]) -> tuple[list[TypedEvent], dict[str, dict]]:
        ids = [row["first_event_id"] for row in rows if row.get("first_event_id")]
        stored = {row["id"]: TypedEvent.model_validate(row["event"])
                  for row in self.repo.events_by_ids(ids)}
        raw_copies: dict[str, dict] = {}
        missing = [row for row in rows if row.get("first_event_id") not in stored]
        refs = [ref for row in missing for ref in row.get("first_event_refs") or []]
        if refs and self.citation_source is not None and hasattr(self.citation_source, "fetch_refs"):
            try:
                fetched, raw_copies, _reasons = self.citation_source.fetch_refs(refs)
            except Exception:  # noqa: BLE001 - inability to re-fetch a citation makes the key unresolved
                fetched, raw_copies = (), {}
            wanted = {row["first_event_id"] for row in missing}
            stored.update({event.id: event for event in fetched if event.id in wanted})
        return [stored[event_id] for event_id in ids if event_id in stored], raw_copies

    def judge(self, playbook: BaselinePlaybook) -> Iterator[Match]:
        if playbook.spec.measure == "rate":
            yield from self._judge_rate(playbook)
            return
        observations = self.repo.baseline_observations_for_spec(
            self.hunt_id, playbook.id, playbook.spec.version,
        )
        updated_total = unresolved = common = first_total = groups = 0
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
            cited_rows = first_seen[:BASELINE_CITATION_CAP]
            events, raw_copies = self._citation_events(cited_rows)
            if not events:
                for row in first_seen:
                    row.update(verdict="unresolved", reason="first citation event is not retained")
                self.repo.upsert_baseline_observations(first_seen)
                unresolved += len(first_seen)
                first_total -= len(first_seen)
                continue
            group_key = f"baseline:{playbook.id}:{scope}"
            self._pending_group = (group_key, first_seen)
            groups += 1
            yield Match(
                playbook_id=playbook.id,
                claim=self._claim(playbook, scope, first_seen, facts, len(events)),
                claim_type="anomaly", events=events, predicate=_predicate(events, playbook),
                ts=min(event.ts for event in events), severity="info", proposed_lane="lead",
                confidence="medium", entities=_entities(events),
                notes=["baseline deviations are capped at the lead lane"], group_key=group_key,
                raw_copies=raw_copies,
            )
        self.spec_stats[playbook.id] = {
            "observations": updated_total, "unresolved": unresolved,
            "common": common, "first_seen": first_total, "groups": groups,
            "window_failure": window_failure, "history_failure": history_failure,
        }

    def attach_candidate(self, match: Match, candidate_id: str) -> None:
        pending = self._pending_group
        if pending is None or pending[0] != match.group_key:
            return
        self.repo.upsert_baseline_observations(
            {**row, "candidate_id": candidate_id} for row in pending[1]
        )
        self._pending_group = None


def _history_cell_state(coverage: dict) -> str:
    if coverage.get("status") == "not_applicable":
        return "not_applicable_no_events"
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
             if not (cell["target"] == "*" and cell["partition"] == "window")
             and not cell["target"].startswith("baseline:")
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
        hunt_id, playbook.id, playbook.spec.version, "*", "window", state,
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
    network_record = hunt["manifest"].get("internal_networks") or {}
    networks_configured = network_record.get("source") == "configured"
    build_specs = [spec for spec in specs if not spec.requires_configured_networks or networks_configured]
    targets = list(hunt["manifest"]["targets"])
    applicable_specs = baseline_applicability(repo.source_profiles(hunt_id), contracts, targets, specs)
    build_ids = {spec.id for spec in build_specs}
    build_applicability = {
        target: spec_ids & build_ids for target, spec_ids in applicable_specs.items()
    }
    history_source = source or HuntHistorySource(client, contracts or {})
    if snapshot is None:
        writer = LookbackWriter(
            repo, history_source, site=str(config["site"]), specs=build_specs,
            normalizer=NORMALIZER_VERSION,
            budget=LookbackBudget(
                queries=int(budget.get("queries", 200)), records=int(budget.get("records", 5_000_000)),
                seconds=float(budget.get("seconds", 1800)),
            ),
            context=KeyContext(is_internal=netdef.current().is_internal),
            parent_carry=CarryInStore(repo, hunt_id),
            network_digest=network_record.get("digest") if networks_configured else None,
            applicable_specs=build_applicability,
        )
        try:
            result = writer.fill(
                hunt_id=hunt_id, targets=targets,
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
    resolve_window_exec_pairs(repo, hunt_id, window)
    if snapshot is None:
        snapshot = SnapshotPlanner(repo).freeze(
            hunt_id=hunt_id, window_start=window.start, lookback=timedelta(days=history_days),
            min_live_hours=min_live_hours, site=str(config["site"]),
            targets=targets, specs=specs, history_gaps=result.gaps,
            network_digest=network_record.get("digest") if networks_configured else None,
            applicable_specs=applicable_specs,
        )
    _write_history_cells(repo, hunt_id, snapshot, specs, owner_token)
    view = SnapshotView(
        repo, hunt_id, window, snapshot, min_live_hours=min_live_hours,
        networks_configured=networks_configured,
        citation_source=history_source,
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
    source_failure = any(gap.state in {"partial", "failed"} for gap in result.gaps) or any(
        gap.get("state") in {"partial", "failed"}
        for coverage in snapshot.get("coverage", {}).values()
        for gap in coverage.get("gaps") or []
    )
    staging_failure = any(
        "compact baseline stage failed" in str(reason)
        for cell in repo.rule_cells(hunt_id)
        for reason in (cell.get("detail") or {}).get("reasons", [])
    )
    summary = {
        "finished": True, "status": status, "snapshot_digest": snapshot["digest"],
        "snapshot_status": snapshot["status"], "specs": view.spec_stats,
        "stage_failed": source_failure or staging_failure,
        "lookback": {"complete": result.complete, "gaps": len(result.gaps),
                     "queries": result.queries, "records": result.records},
    }
    # Hunt execution consumes `stage_failed`; the established baseline task outcome remains result-shaped so
    # this coverage truth does not perturb unrelated scheduler/task goldens.
    task_outcome = {key: value for key, value in summary.items() if key != "stage_failed"}
    repo.update_task(task_id, "partial" if status == "partial" else "evaluated", outcome=task_outcome,
                     owner_token=owner_token)
    return summary
