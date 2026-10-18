"""The deterministic sweep: plan partitions, stream every partition through normalization and all
playbooks, publish direct findings immediately, and keep an exact per-rule coverage ledger."""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from romulus.decide.policy import decide
from romulus.detect.base import Match, Playbook
from romulus.detect.registry import fresh_pack
from romulus.evidence.normalize import normalize_hits
from romulus.sources.es import ElasticClient
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Window
from romulus.sources.profile import FieldContract
from romulus.store.db import digest
from romulus.store.repo import Repo

log = logging.getLogger("romulus.sweep")

PARTITION_MAX_DOCS = 120_000
HOST_DATASETS = ["linux.audit", "systemd.journal", "apache.access", "apache.error"]


BUCKET_SECONDS = 300
MIN_SPLIT = timedelta(seconds=5)


def plan_partitions(client: ElasticClient, target: str, contract: FieldContract, window: Window,
                    filters: list[Predicate]) -> list[tuple[Window, int]]:
    """5-minute histogram with exact counts; merge consecutive buckets up to PARTITION_MAX_DOCS.
    A single bucket above the limit becomes its own partition and is split adaptively at run time."""
    h = execute(client, SearchIntent(kind="histogram", target=target, window=window, filters=filters,
                                     interval_seconds=BUCKET_SECONDS), contract)
    if h.completeness != Completeness.complete:
        raise RuntimeError(f"cannot plan partitions for {target}: {h.reasons} {h.error}")
    parts: list[tuple[Window, int]] = []
    cur_start, cur_n = None, 0
    for b in h.buckets:
        bs = max(datetime.fromisoformat(b["key"].replace("Z", "+00:00")), window.start)
        be = min(datetime.fromisoformat(b["key"].replace("Z", "+00:00")) + timedelta(seconds=BUCKET_SECONDS),
                 window.end)
        if bs >= be:
            continue
        n = b["count"]
        if cur_start is not None and cur_n + n > PARTITION_MAX_DOCS:
            parts.append((Window(start=cur_start, end=bs), cur_n))
            cur_start, cur_n = None, 0
        if cur_start is None:
            cur_start = bs
        cur_n += n
        last_end = be
    if cur_start is not None:
        parts.append((Window(start=cur_start, end=last_end), cur_n))
    return parts


class Sweep:
    def __init__(self, repo: Repo, client: ElasticClient, hunt_id: str, window: Window,
                 contracts: dict[str, FieldContract], on_candidate: Callable[[dict], None] | None = None):
        self.repo, self.client, self.hunt_id, self.window = repo, client, hunt_id, window
        self.contracts = contracts
        self.on_candidate = on_candidate or (lambda c: None)
        self.pack: list[Playbook] = fresh_pack()
        self.partial_reasons: list[str] = []
        self.stats = {"partitions": 0, "records": 0, "events": 0, "candidates": 0, "skips": {}, "errors": 0}

    # -------------------------------------------------------------------------------------
    def _publish(self, m: Match, task_id: str | None, raw_sources: dict[str, dict]):
        d = decide(m, self.hunt_id)
        self.repo.save_evidence(self.hunt_id, m.events, raw_sources, task_id)
        row = {"id": d.candidate_id, "hunt_id": self.hunt_id, "rule_id": m.playbook_id,
               "rule_version": next(p.version for p in self.pack if p.id == m.playbook_id),
               "claim": m.claim, "claim_type": m.claim_type, "event_ids": [e.id for e in m.events],
               "predicate_fields": [{"field": p.field, "value": p.value, "origin": p.origin} for p in m.predicate],
               "entities": [list(x) for x in m.entities], "ts": m.ts, "severity": d.severity,
               "confidence": d.confidence, "lane": d.lane, "priority": d.priority,
               "priority_reasons": d.priority_reasons, "gate_results": d.gates,
               "benign_alternatives": list(next(p.benign for p in self.pack if p.id == m.playbook_id)),
               "next_checks": list(next(p.next_checks for p in self.pack if p.id == m.playbook_id)),
               "source_case_id": None}
        row["gate_results"] = {**d.gates, "_notes": d.notes}
        if self.repo.save_candidate(row):
            self.stats["candidates"] += 1
            self.on_candidate(row)

    def _filters_for(self, target: str) -> list[Predicate]:
        if "host" in target:
            return [Predicate(field="event.dataset", op="in", value=HOST_DATASETS)]
        return []

    # -------------------------------------------------------------------------------------
    def run_target(self, target: str):
        contract = self.contracts[target]
        filters = self._filters_for(target)
        parts = plan_partitions(self.client, target, contract, self.window, filters)
        for w, est in parts:
            self.run_partition(target, contract, filters, w, est)

    def run_partition(self, target: str, contract: FieldContract, filters: list[Predicate], w: Window, est: int):
        if est > PARTITION_MAX_DOCS and (w.end - w.start) > MIN_SPLIT * 2:
            # exact histogram count already exceeds the limit: subdivide before fetching anything
            mid = w.start + (w.end - w.start) / 2
            self.run_partition(target, contract, filters, Window(start=w.start, end=mid), est // 2)
            self.run_partition(target, contract, filters, Window(start=mid, end=w.end), est - est // 2)
            return
        pkey = w.key()
        cap = max(PARTITION_MAX_DOCS, int(est * 1.2) + 1000)
        intent = SearchIntent(kind="raw", target=target, window=w, filters=filters, max_records=cap, purpose="sweep")
        tid = "t-" + digest({"h": self.hunt_id, "target": target, "w": pkey})[:20]
        self.repo.upsert_task(tid, self.hunt_id, "sweep", "sweep", intent.model_dump(mode="json"), tid)
        # No skip-on-resume: aggregate playbooks must consume every partition again or their
        # coverage would claim completeness over a subset. Writes are idempotent, so re-reading
        # is safe (attempts are counted and visible).
        self.repo.update_task(tid, "leased", attempt=True)
        out = execute(self.client, intent, contract)
        capped = any(r.startswith("cap:") for r in out.reasons)
        if capped and (w.end - w.start) > MIN_SPLIT * 2:
            # Capped: never accept a partial partition when it can be subdivided. Split in half
            # and evaluate each half; this task is recorded as superseded by its children.
            mid = w.start + (w.end - w.start) / 2
            self.repo.update_task(tid, "split", outcome={"completeness": out.completeness, "reasons": out.reasons,
                                                         "total": out.total, "returned": out.returned,
                                                         "children": [f"{w.start.isoformat()}/{mid.isoformat()}",
                                                                      f"{mid.isoformat()}/{w.end.isoformat()}"]})
            half = (out.total or est) // 2
            self.run_partition(target, contract, filters, Window(start=w.start, end=mid), half)
            self.run_partition(target, contract, filters, Window(start=mid, end=w.end), half)
            return
        self.stats["partitions"] += 1
        self.stats["records"] += out.returned
        self.repo.update_task(tid, "executed", outcome={"completeness": out.completeness, "reasons": out.reasons,
                                                        "total": out.total, "returned": out.returned})
        if out.completeness == Completeness.failed:
            self.partial_reasons.append(f"{target} {pkey}: {out.error}")
            for pb in self.pack:
                self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, target, pkey, "executed_failed", 0, 0,
                                        {"error": out.error})
            self.repo.update_task(tid, "failed", error=out.error)
            return
        events, skips, errors = normalize_hits(out.records)
        self.stats["events"] += len(events)
        self.stats["errors"] += len(errors)
        for k, v in skips.items():
            self.stats["skips"][k] = self.stats["skips"].get(k, 0) + v
        raw_sources = {f"{r['_index']}/{r['_id']}": r["_source"] for r in out.records}
        partial = out.completeness != Completeness.complete or bool(errors)
        if partial:
            self.partial_reasons.append(f"{target} {pkey}: {out.reasons or ''} normalization_errors={len(errors)}")
        families = {e.family for e in events}
        for pb in self.pack:
            before_eval, before_missing = pb.evaluated, pb.missing_required
            matches = pb.consume(events)
            for m in matches:
                self._publish(m, tid, raw_sources)
            if pb.kind == "aggregate":
                # aggregates retain examples: stash raw copies of their retained events now
                self._retain_aggregate_raw(pb, raw_sources)
            evaluated = pb.evaluated - before_eval
            missing = pb.missing_required - before_missing
            if not (set(pb.families) & families) and evaluated == 0:
                state = "not_applicable_no_events" if not partial else "evaluated_partial"
            elif pb.kind == "aggregate":
                state = "evaluated_partial" if (partial or missing) else "evaluated_complete"
            elif matches:
                state = "match_on_partial" if partial else "matched"
            else:
                state = "evaluated_partial" if (partial or missing) else "no_match_complete"
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, target, pkey, state, len(matches), evaluated,
                                    {"missing_required": missing, "reasons": out.reasons})
        self.repo.update_task(tid, "evaluated")

    def _retain_aggregate_raw(self, pb: Playbook, raw_sources: dict[str, dict]):
        groups = getattr(pb, "groups", {})
        keep = getattr(self, "_agg_raw", None)
        if keep is None:
            keep = self._agg_raw = {}
        for evs in groups.values():
            for e in evs:
                for r in e.raw:
                    if r.key in raw_sources and r.key not in keep:
                        keep[r.key] = raw_sources[r.key]

    def finalize(self):
        agg_raw = getattr(self, "_agg_raw", {})
        for pb in self.pack:
            if pb.kind != "aggregate":
                continue
            ms = pb.finalize()
            for m in ms:
                self._publish(m, None, agg_raw)
            cells = [c for c in self.repo.rule_cells(self.hunt_id) if c["rule_id"] == pb.id]
            any_partial = any(c["state"] in ("evaluated_partial", "executed_failed") for c in cells)
            state = ("match_on_partial" if ms else "evaluated_partial") if any_partial else \
                    ("matched" if ms else "no_match_complete")
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, "*", "window", state, len(ms),
                                    sum(c["evaluated"] for c in cells))
