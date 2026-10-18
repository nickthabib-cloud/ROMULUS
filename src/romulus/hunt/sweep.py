"""The deterministic sweep: plan partitions, stream every partition through normalization and all
playbooks, publish direct findings immediately, and keep an exact per-rule coverage ledger."""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from romulus.detect.base import Match, Playbook
from romulus.detect.registry import fresh_pack
from romulus.evidence.normalize import normalize_hits
from romulus.hunt.publish import publish_match
from romulus.sources.es import ElasticClient
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Window
from romulus.sources.profile import FieldContract
from romulus.store.db import digest
from romulus.store.repo import Repo

log = logging.getLogger("romulus.sweep")

PARTITION_MAX_DOCS = 120_000
HOST_DATASETS = ["linux.audit", "systemd.journal", "apache.access", "apache.error"]
NET_FAMILIES = {"net_alert", "net_flow", "dns_query", "http_tx", "file_transfer", "tls_session", "ssh_session"}
DATASET_FAMILIES = {"linux.audit": {"process_exec"}, "systemd.journal": {"auth", "privilege_use"},
                    "apache.access": {"http_access"}, "apache.error": {"web_error"},
                    **{f"suricata.eve.{t}": NET_FAMILIES for t in ("alert", "flow", "netflow", "dns", "http",
                                                                  "fileinfo", "tls", "ssh")}}
ALL_FAMILIES = frozenset({"*"})


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
        bs = max(datetime.fromisoformat(b["key"]), window.start)
        be = min(datetime.fromisoformat(b["key"]) + timedelta(seconds=BUCKET_SECONDS),
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
                 contracts: dict[str, FieldContract], on_candidate: Callable[[dict], None] | None = None,
                 heartbeat: Callable[[], None] | None = None):
        self.repo, self.client, self.hunt_id, self.window = repo, client, hunt_id, window
        self.contracts = contracts
        self.on_candidate = on_candidate or (lambda c: None)
        self.heartbeat = heartbeat or (lambda: None)
        self.pack: list[Playbook] = fresh_pack()
        self.partial_reasons: list[str] = []
        self.stats = {"partitions": 0, "records": 0, "events": 0, "candidates": 0, "skips": {}, "errors": 0}

    # -------------------------------------------------------------------------------------
    def _publish(self, m: Match, task_id: str | None, raw_sources: dict[str, dict]):
        playbook = next(playbook for playbook in self.pack if playbook.id == m.playbook_id)
        row = publish_match(self.repo, self.hunt_id, playbook, m, task_id, raw_sources)
        if row is not None:
            self.stats["candidates"] += 1
            self.on_candidate(row)

    def _filters_for(self, target: str) -> list[Predicate]:
        if "host" in target:
            return [Predicate(field="event.dataset", op="in", value=HOST_DATASETS)]
        return []

    # -------------------------------------------------------------------------------------
    def _mark_all(self, target: str, pkey: str, state: str, detail: dict | None = None):
        """Write the same coverage state for every rule on one (target, partition)."""
        for pb in self.pack:
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, target, pkey, state, 0, 0, detail or {})

    def _split(self, target: str, w: Window) -> tuple[Window, Window]:
        """Record children as planned *before* the parent is superseded, so a crash between the two
        leaves visible unexecuted work rather than a silent gap."""
        mid = w.start + (w.end - w.start) / 2
        a, b = Window(start=w.start, end=mid), Window(start=mid, end=w.end)
        self._mark_all(target, a.key(), "planned")
        self._mark_all(target, b.key(), "planned")
        self._mark_all(target, w.key(), "split", {"children": [a.key(), b.key()]})
        return a, b

    def run_target(self, target: str):
        contract = self.contracts[target]
        filters = self._filters_for(target)
        try:
            self.heartbeat()
            parts = plan_partitions(self.client, target, contract, self.window, filters)
            self.heartbeat()
        except Exception as e:  # noqa: BLE001 - one source failing must not hide the others
            reason = f"partition planning failed: {e}"[:300]
            self.partial_reasons.append(f"{target}: {reason}")
            self._mark_all(target, f"plan:{self.window.key()}", "executed_failed", {"error": reason})
            return
        # persist every planned (rule x target x partition) cell first: anything never executed
        # stays visibly 'planned' and can never be read as a complete negative
        for w, _est in parts:
            self._mark_all(target, w.key(), "planned")
        for w, est in parts:
            self.run_partition(target, contract, filters, w, est)

    def run_partition(self, target: str, contract: FieldContract, filters: list[Predicate], w: Window, est: int):
        self.heartbeat()
        if est > PARTITION_MAX_DOCS and (w.end - w.start) > MIN_SPLIT * 2:
            # exact histogram count already exceeds the limit: subdivide before fetching anything
            a, b = self._split(target, w)
            self.run_partition(target, contract, filters, a, est // 2)
            self.run_partition(target, contract, filters, b, est - est // 2)
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
        self.heartbeat()
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
            a, b = self._split(target, w)
            self.run_partition(target, contract, filters, a, half)
            self.run_partition(target, contract, filters, b, half)
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
        # records retrieved but of a dataset/event type no normalizer supports: we cannot say what
        # they contain, so no rule may claim a complete negative over this partition
        unsupported = {k: v for k, v in skips.items()
                       if k.startswith("dataset:") or k.startswith("suricata event_type")}
        partial = out.completeness != Completeness.complete or bool(errors) or bool(unsupported)
        if partial:
            self.partial_reasons.append(f"{target} {pkey}: {out.reasons or ''} normalization_errors={len(errors)}"
                                        + (f" unsupported_records={sum(unsupported.values())}" if unsupported else ""))
        families = {e.family for e in events}
        # Which event families the problems could have hidden. A retrieval problem affects every
        # rule; a normalization error affects only families its dataset feeds; an unsupported
        # dataset could hold anything, so it affects every rule.
        affected = ALL_FAMILIES if (out.completeness != Completeness.complete or unsupported) else set()
        for _rid, msg in errors:
            if affected is ALL_FAMILIES:
                break
            fams = DATASET_FAMILIES.get(msg.split(":", 1)[0].strip())
            affected = ALL_FAMILIES if fams is None else affected | fams
        for pb in self.pack:
            rule_partial = affected is ALL_FAMILIES or bool(set(pb.families) & affected)
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
                state = "not_applicable_no_events" if not rule_partial else "evaluated_partial"
            elif pb.kind == "aggregate":
                state = "evaluated_partial" if (rule_partial or missing) else "evaluated_complete"
            elif matches:
                state = "match_on_partial" if rule_partial else "matched"
            else:
                state = "evaluated_partial" if (rule_partial or missing) else "no_match_complete"
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, target, pkey, state, len(matches), evaluated,
                                    {"missing_required": missing, "reasons": out.reasons})
        self.repo.update_task(tid, "evaluated")

    def _retain_aggregate_raw(self, pb: Playbook, raw_sources: dict[str, dict]):
        keep = getattr(self, "_agg_raw", None)
        if keep is None:
            keep = self._agg_raw = {}
        for e in pb.retained_events():
            for r in e.raw:
                if r.key in raw_sources and r.key not in keep:
                    keep[r.key] = raw_sources[r.key]

    def finalize(self):
        self.heartbeat()
        agg_raw = getattr(self, "_agg_raw", {})
        for pb in self.pack:
            if pb.kind != "aggregate":
                continue
            self.heartbeat()
            ms = pb.finalize()
            for m in ms:
                self._publish(m, None, agg_raw)
            cells = [c for c in self.repo.rule_cells(self.hunt_id)
                     if c["rule_id"] == pb.id and c["target"] != "*" and c["state"] != "split"]
            any_partial = any(c["state"] in ("evaluated_partial", "executed_failed", "planned", "match_on_partial")
                              for c in cells)
            evaluated = sum(c["evaluated"] or 0 for c in cells)
            if any_partial or not cells:
                state = "match_on_partial" if ms else "evaluated_partial"
            elif ms:
                state = "matched"
            elif evaluated == 0:
                # nothing of this rule's families was in scope: that is not a negative
                state = "not_applicable_no_events"
            else:
                state = "no_match_complete"
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, "*", "window", state, len(ms), evaluated)
