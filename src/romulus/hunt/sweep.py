"""The deterministic sweep: plan partitions, stream every partition through normalization and all
playbooks, publish direct findings immediately, and keep an exact per-rule coverage ledger."""
from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta

from romulus.detect.base import Match, Playbook
from romulus.detect.bounded import StateBudget, StateExhausted, live_stores
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON
from romulus.detect.registry import fresh_pack
from romulus.evidence.normalize import (
    BOOT_FILL_FAMILIES,
    BOOT_INTERVAL_ORIGIN,
    BootIntervals,
    normalize_hits,
)
from romulus.evidence.typed import TypedEvent
from romulus.hunt.publish import publish_match
from romulus.hunt.stage import EventStage
from romulus.sources.es import ElasticClient, fetch_limit
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Predicate, SearchIntent, Window
from romulus.sources.profile import FieldContract
from romulus.store.db import digest
from romulus.store.repo import Repo

log = logging.getLogger("romulus.sweep")

PARTITION_MAX_DOCS = 120_000
# planned cells are written before any partition runs, this many partitions per transaction
PLANNED_CHUNK = 500
HOST_DATASETS = ["linux.audit", "systemd.journal", "apache.access", "apache.error"]
NET_FAMILIES = {"net_alert", "net_flow", "dns_query", "http_tx", "file_transfer", "tls_session", "ssh_session"}
# linux.audit now also yields `auth` (USER_LOGIN/USER_START), so an unparseable audit group may hide one.
# A login group that fails is tagged linux.audit.auth; it takes every record of its event, so it may also hide
# an exec, socket or file record of that event and carries the whole audit family set.
_AUDIT_ADMIN = {"account_change", "service_change", "audit_config", "system_state"}
DATASET_FAMILIES = {"linux.audit": {"process_exec", "net_socket", "auth", "file_change"} | _AUDIT_ADMIN,
                    "linux.audit.socket": {"net_socket"}, "linux.audit.file": {"file_change"},
                    "linux.audit.auth": {"process_exec", "net_socket", "auth", "file_change"} | _AUDIT_ADMIN,
                    "linux.audit.admin": _AUDIT_ADMIN,
                    "arkime.session": {"net_session"},
                    "systemd.journal": {"auth", "privilege_use", "service_change"},
                    "apache.access": {"http_access"}, "apache.error": {"web_error"},
                    **{f"suricata.eve.{t}": NET_FAMILIES for t in ("alert", "flow", "netflow", "dns", "http",
                                                                  "fileinfo", "tls", "ssh")}}
ALL_FAMILIES = frozenset({"*"})
WINDOW_ROLLUP_PARTIAL = ("whole-window result over partitions of which one or more were partial, failed or "
                         "unexecuted (listed separately)")


BUCKET_SECONDS = 300
MIN_SPLIT = timedelta(seconds=5)
# The audit action that holds a hunt's boot-interval map, written once when the sweep has read every partition.
BOOT_INTERVALS_AUDIT = "hunt.boot_intervals"
# How many boot-placement items the sweep summary lists by name; the boot-interval map record holds every one.
BOOT_LISTED = 100
BOOT_BLIND_LISTED = 20
# A rule-coverage cell recording that sweep-time boot placement was contradicted on some host
BOOT_PLACEMENT_PARTITION = "boot-placement"


def stored_boot_intervals(repo: Repo, hunt_id: str) -> BootIntervals:
    """The boot-interval map the hunt's sweep recorded; empty (it places nothing) when there is none."""
    row = repo.latest_audit(hunt_id, BOOT_INTERVALS_AUDIT) if hasattr(repo, "latest_audit") else None
    return BootIntervals.from_json((row or {}).get("detail") or {})


def state_budget(settings, stage_dir) -> StateBudget:
    """The hunt's state budget from the settings (defaults when a setting is absent)."""
    disk_gb = float(getattr(settings, "state_disk_gb", 0) or 0)
    reserve_gb = getattr(settings, "state_disk_reserve_gb", None)
    memory_mb = getattr(settings, "state_memory_mb", None)
    kwargs = {}
    if reserve_gb is not None:
        kwargs["reserve_floor"] = int(float(reserve_gb) * 2**30)
    if memory_mb is not None:
        kwargs["memory_total"] = int(memory_mb) * 2**20
    return StateBudget(stage_dir, disk_total=int(disk_gb * 2**30) or None, **kwargs)


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
                 heartbeat: Callable[[], None] | None = None, stage_dir=None, prefetch: bool | None = None):
        self.repo, self.client, self.hunt_id, self.window = repo, client, hunt_id, window
        # Fetch the next partition while this one is evaluated (the client's setting unless given). It changes
        # when a partition's records are read, never what is read or the order partitions are evaluated in.
        settings = getattr(client, "settings", None)
        self.prefetch = bool(getattr(settings, "sweep_prefetch", False)) if prefetch is None else prefetch
        self._next: tuple | None = None            # the partition after the current top-level one
        self._ahead: tuple[str, Future] | None = None
        self._pool: ThreadPoolExecutor | None = None
        self.contracts = contracts
        self.on_candidate = on_candidate or (lambda c: None)
        beat = heartbeat or (lambda: None)

        def heartbeat_and_touch():
            beat()
            for pb in self.pack:                # a live spill is never mistaken for a killed process's leftover
                if pb._spill is not None:
                    pb._spill.touch()
        self.heartbeat = heartbeat_and_touch
        self.stage_dir = stage_dir
        # One state budget for the hunt: the disk every playbook's spill may use (and the free space left on the
        # stage volume), and the memory their hot sets share. Read the stage volume's free space before the sweep.
        self.budget = state_budget(settings, stage_dir)
        self.pack: list[Playbook] = fresh_pack()
        for pb in self.pack:
            pb.spill_dir = stage_dir          # a playbook's on-disk join tables live beside the event stage
            pb.budget = self.budget
        # one guaranteed floor per live store of the pack (a store shared by several rules counts once), and one for
        # the event stage, which holds the citations of every rule
        self.budget.plan(live_stores(self.pack) + 1)
        self._stage_account = self.budget.account("event_stage")
        self._stage_size = 0
        self.partial_reasons: list[str] = []
        preflight = self.budget.preflight()
        if preflight:
            self.partial_reasons.append(f"state budget: {preflight}; rules evaluate only records that need no new "
                                        f"state")
        # Built as partitions are read, in time order per target: each batch's events are placed with what has
        # been observed so far. Expansion and the context pass use the whole map, recorded at finalize.
        self.boots = BootIntervals()
        self.stats = {"partitions": 0, "records": 0, "events": 0, "candidates": 0, "skips": {}, "errors": 0,
                      "boot": {"recorded": 0, "from_interval": 0, "unknown": 0}}

    # -------------------------------------------------------------------------------------
    def _sources_for(self, m: Match, raw_sources: dict[str, dict]) -> dict[str, dict]:
        """Raw copies for a match published while a partition is read: this partition's, and from the event stage
        for a cited record a staged rule held from an earlier partition."""
        missing = [e for e in m.events if any(r.key not in raw_sources for r in e.raw)]
        stage = getattr(self, "_stage", None)
        if not missing or stage is None:
            return raw_sources
        return {**stage.raw_sources(missing), **raw_sources}

    def _stage_put(self, events: list[TypedEvent], raw_sources: dict[str, dict],
                   held: list[tuple[str, TypedEvent]] = (), released: list[tuple[str, list[str]]] = ()) -> None:
        """Stage citations (kept to the end) and playbooks' holds of interval bounds, then release the holds they
        let go, charging the stage's growth to its own account of the hunt's state budget (freed pages are reused,
        so the charge follows the most the stage held at once). A write the volume cannot take marks the budget
        broken: those citations are lost to their rules, which say so."""
        import sqlite3
        stage = self._event_stage()
        try:
            if events:
                stage.put(events, raw_sources)
            stage.hold(list(held), raw_sources)
            for owner, ids in released:
                stage.release(owner, ids)
        except sqlite3.OperationalError as exc:
            self.budget.fail(f"writing the event stage failed ({exc})")
            for pb in self.pack:
                if pb.staged:
                    pb.note_limit("stage", f"the event stage could not take this partition's citations "
                                           f"({self.budget.broken}); findings that cite them are not computed")
            return
        size = stage.db.execute("PRAGMA page_count").fetchone()[0] * stage.db.execute("PRAGMA page_size").fetchone()[0]
        if size > self._stage_size:
            self.budget.charge(self._stage_account, size - self._stage_size)
            self._stage_size = size

    def _publish(self, m: Match, task_id: str | None, raw_sources: dict[str, dict]):
        playbook = next(playbook for playbook in self.pack if playbook.id == m.playbook_id)
        row = publish_match(self.repo, self.hunt_id, playbook, m, task_id, raw_sources)
        if row is not None:
            self.stats["candidates"] += 1
            self.on_candidate(row)

    def _filters_for(self, target: str) -> list[Predicate]:
        if "host" in target:
            # recorded so the report can list the target's other datasets as not assessed
            self.stats.setdefault("dataset_filter", {})[target] = list(HOST_DATASETS)
            return [Predicate(field="event.dataset", op="in", value=HOST_DATASETS)]
        return []

    # -------------------------------------------------------------------------------------
    def _cell(self, pb: Playbook, target: str, pkey: str, state: str, matched: int = 0, evaluated: int = 0,
              detail: dict | None = None) -> dict:
        return {"rule_id": pb.id, "version": pb.version, "target": target, "partition": pkey, "state": state,
                "matched": matched, "evaluated": evaluated, "detail": detail or {}}

    def _mark_all(self, target: str, pkey: str, state: str, detail: dict | None = None):
        """Write the same coverage state for every rule on one (target, partition), in one transaction."""
        self.repo.set_rule_cells(self.hunt_id, [self._cell(pb, target, pkey, state, detail=detail)
                                                for pb in self.pack])

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
        for start in range(0, len(parts), PLANNED_CHUNK):
            self.repo.set_rule_cells(self.hunt_id, [self._cell(pb, target, w.key(), "planned")
                                                    for w, _est in parts[start:start + PLANNED_CHUNK]
                                                    for pb in self.pack])
        try:
            for index, (w, est) in enumerate(parts):
                following = parts[index + 1] if index + 1 < len(parts) else None
                self._next = (target, contract, filters, *following) if following else None
                self.run_partition(target, contract, filters, w, est)
        finally:
            self._next = None
            self._stop_prefetch()

    @staticmethod
    def _raw_intent(target: str, filters: list[Predicate], w: Window, est: int) -> SearchIntent:
        cap = max(PARTITION_MAX_DOCS, int(est * 1.2) + 1000)
        return SearchIntent(kind="raw", target=target, window=w, filters=filters, max_records=cap, purpose="sweep")

    def _fetch(self, intent: SearchIntent, contract: FieldContract):
        """The partition's records: the prefetched outcome when it is this very intent, else fetched now."""
        if self._ahead is not None and self._ahead[0] == intent.model_dump_json():
            future = self._ahead[1]
            self._ahead = None
            return future.result()
        return execute(self.client, intent, contract)

    def _start_prefetch(self) -> None:
        """Begin fetching the next top-level partition on the background thread, when it will be fetched whole."""
        if not self.prefetch or self._next is None or self._ahead is not None:
            return
        target, contract, filters, w, est = self._next
        self._next = None
        if est > PARTITION_MAX_DOCS and (w.end - w.start) > MIN_SPLIT * 2:
            return                                   # it is split before anything is fetched
        intent = self._raw_intent(target, filters, w, est)
        if self._pool is None:
            self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="romulus-sweep-prefetch")
        client = self.client
        self._ahead = (intent.model_dump_json(), self._pool.submit(lambda: execute(client, intent, contract)))

    def _stop_prefetch(self) -> None:
        """Drop a prefetch nobody will use (the target stopped early) and release the thread."""
        if self._ahead is not None:
            self._ahead[1].cancel()
            self._ahead = None
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    def _count(self, target: str, contract: FieldContract, filters: list[Predicate], w: Window) -> int | None:
        """The exact number of records in a window, or None when the source does not say exactly."""
        out = execute(self.client, SearchIntent(kind="histogram", target=target, window=w, filters=filters,
                                                interval_seconds=BUCKET_SECONDS, purpose="sweep count"), contract)
        if out.completeness == Completeness.complete and out.total_relation == "eq" and out.total is not None:
            return out.total
        return None

    def run_partition(self, target: str, contract: FieldContract, filters: list[Predicate], w: Window, est: int,
                      *, estimated: bool = False):
        """Evaluate one partition. `est` is the histogram's exact count for a planned partition; for a half of a
        split one (`estimated`) it is only an estimate, so the half is counted before it is fetched."""
        self.heartbeat()
        splittable = (w.end - w.start) > MIN_SPLIT * 2
        if est > PARTITION_MAX_DOCS and splittable:
            # exact histogram count already exceeds the limit: subdivide before fetching anything
            a, b = self._split(target, w)
            self.run_partition(target, contract, filters, a, est // 2, estimated=True)
            self.run_partition(target, contract, filters, b, est - est // 2, estimated=True)
            return
        pkey = w.key()
        intent = self._raw_intent(target, filters, w, est)
        cap = intent.max_records
        tid = "t-" + digest({"h": self.hunt_id, "target": target, "w": pkey})[:20]
        self.repo.upsert_task(tid, self.hunt_id, "sweep", "sweep", intent.model_dump(mode="json"), tid)
        # No skip-on-resume: aggregate playbooks must consume every partition again or their
        # coverage would claim completeness over a subset. Writes are idempotent, so re-reading
        # is safe (attempts are counted and visible).
        self.repo.update_task(tid, "leased", attempt=True)
        mid = w.start + (w.end - w.start) / 2
        children = [f"{w.start.isoformat()}/{mid.isoformat()}", f"{mid.isoformat()}/{w.end.isoformat()}"]
        counted = self._count(target, contract, filters, w) if estimated and splittable else None
        if counted is not None and counted > fetch_limit(cap):
            # The fetch would stop at its cap and be split: split now, without reading records only to drop them.
            # The cap is the same, so the halves and their estimates are those a capped fetch would have given.
            self.heartbeat()
            self.repo.update_task(tid, "split", outcome={"completeness": Completeness.partial,
                                                         "reasons": [f"cap:{cap}<total:{counted}"], "total": counted,
                                                         "returned": 0, "counted": True, "children": children})
            a, b = self._split(target, w)
            self.run_partition(target, contract, filters, a, counted // 2, estimated=True)
            self.run_partition(target, contract, filters, b, counted // 2, estimated=True)
            return
        out = self._fetch(intent, contract)
        self._start_prefetch()
        self.heartbeat()
        capped = any(r.startswith("cap:") for r in out.reasons)
        if capped and splittable:
            # Capped: never accept a partial partition when it can be subdivided. Split in half
            # and evaluate each half; this task is recorded as superseded by its children.
            self.repo.update_task(tid, "split", outcome={"completeness": out.completeness, "reasons": out.reasons,
                                                         "total": out.total, "returned": out.returned,
                                                         "children": children})
            half = (out.total or est) // 2
            a, b = self._split(target, w)
            self.run_partition(target, contract, filters, a, half, estimated=True)
            self.run_partition(target, contract, filters, b, half, estimated=True)
            return
        self.stats["partitions"] += 1
        self.stats["records"] += out.returned
        self.repo.update_task(tid, "executed", outcome={"completeness": out.completeness, "reasons": out.reasons,
                                                        "total": out.total, "returned": out.returned})
        if out.completeness == Completeness.failed:
            self.partial_reasons.append(f"{target} {pkey}: {out.error}")
            self._mark_all(target, pkey, "executed_failed", {"error": out.error})
            self.repo.update_task(tid, "failed", error=out.error)
            return
        events, skips, errors = normalize_hits(out.records, self.boots)
        self.stats["events"] += len(events)
        self._count_boots(events)
        self.stats["errors"] += len(errors)
        for k, v in skips.items():
            self.stats["skips"][k] = self.stats["skips"].get(k, 0) + v
        raw_sources = {f"{r['_index']}/{r['_id']}": r["_source"] for r in out.records}
        # records retrieved but of a dataset/event type no normalizer supports: we cannot say what
        # they contain, so no rule may claim a complete negative over this partition
        unsupported = {k: v for k, v in skips.items()
                       if k.startswith(("dataset:", "suricata event_type"))}
        partial = out.completeness != Completeness.complete or bool(errors) or bool(unsupported)
        if partial:
            self.partial_reasons.append(f"{target} {pkey}: {out.reasons or ''} normalization_errors={len(errors)}"
                                        + (f" unsupported_records={sum(unsupported.values())}" if unsupported else ""))
        families = {e.family for e in events}
        # Which event families the problems could have hidden. A retrieval problem affects every
        # rule; a normalization error affects only families its dataset feeds; an unsupported
        # dataset could hold anything, so it affects every rule.
        affected = ALL_FAMILIES if (out.completeness != Completeness.complete or unsupported) else set()
        # An error tag that feeds no known family could hide anything, so it affects every rule.
        error_affected: set[str] | frozenset[str] = set()
        tags = sorted({msg.split(":", 1)[0].strip() for _rid, msg in errors})
        for tag in tags:
            fams = DATASET_FAMILIES.get(tag)
            if fams is None:
                error_affected = ALL_FAMILIES
                break
            error_affected |= fams
        if affected is not ALL_FAMILIES:
            affected = error_affected
        # The reasons a cell is partial, stated on the cell so the report can list each gap with its cause.
        base_reasons = list(out.reasons)
        if unsupported:
            base_reasons.append(f"unsupported_records={sum(unsupported.values())} (no normalizer; could hold any "
                                f"behavior): {'; '.join(sorted(unsupported))}")
        unmapped = [tag for tag in tags if tag not in DATASET_FAMILIES]
        error_reason = (f"normalization_errors={len(errors)} in {', '.join(tags)}"
                        + (f"; {', '.join(unmapped)} feeds no known event family, so every rule is partial"
                           if unmapped else "")) if errors else ""
        cells: list[dict] = []
        # events the joining aggregates may cite later, by id: several playbooks stage the same events, and each
        # is serialized to the stage once per partition (the first staged copy of an id is kept)
        staged: dict[str, TypedEvent] = {}
        held: list[tuple[str, TypedEvent]] = []          # (playbook, event) holds of interval bounds
        released: list[tuple[str, list[str]]] = []       # (playbook, ids) holds the playbooks let go
        for pb in self.pack:
            rule_partial = affected is ALL_FAMILIES or bool(set(pb.families) & affected)
            before_eval, before_missing, before_capped = pb.evaluated, pb.missing_required, pb.capped
            before_assumed = pb.direction_assumed
            before_limits = {name: limit.records for name, limit in pb.limits.items()}
            # Every rule reads every batch, whatever the state budget: a store in no-growth mode refuses only
            # records that need a new key in it (each rule's own refusal path), and every match that needs no new
            # state still publishes.
            try:
                matches = pb.consume(events)
            except StateExhausted as exc:
                # a write to the stage volume failed mid-batch (a rule that writes rows directly): the records it
                # had not evaluated yet are refused, counted exactly
                matches = []
                pb.refuse_unevaluated(events, pb.evaluated - before_eval + pb.missing_required - before_missing
                                      + pb.capped - before_capped,
                                      f"a write to the stage volume failed ({exc}); this rule's later records of "
                                      f"the batch are not evaluated")
            for m in matches:
                self._publish(m, tid, self._sources_for(m, raw_sources) if pb.staged else raw_sources)
            if pb.staged:
                # joining aggregates: full events and their raw copies go to disk, not memory. Below the stage
                # volume's reserve the stage takes only strong rules' citations; another rule's held examples are
                # then not loadable, and its finalize says so.
                drained = pb.drain_staged()
                held_ids, released_ids = pb.drain_bounds()
                if released_ids:
                    released.append((pb.id, released_ids))
                if drained and self.budget.hard and pb.state_slice != "strong":
                    pb.note_limit("stage", f"the event stage took no new citation of this rule "
                                           f"({self.budget.hard}); its findings that cite them are not computed")
                else:
                    # an event returned more often than it is held is also staged to be kept
                    holds = Counter(held_ids)
                    copies = Counter(event.id for event in drained)
                    for event in drained:
                        if copies[event.id] > holds[event.id]:
                            staged.setdefault(event.id, event)
                    for event in {event.id: event for event in drained if holds[event.id]}.values():
                        held.extend([(pb.id, event)] * holds[event.id])
            elif pb.kind == "aggregate":
                # aggregates retain examples: stash raw copies of their retained events now
                self._retain_aggregate_raw(pb, raw_sources)
            evaluated = pb.evaluated - before_eval
            missing = pb.missing_required - before_missing
            # records a full state budget kept from evaluation: never a clean evaluation of this partition
            capped = pb.capped - before_capped
            # records skipped or judged for a direction the default internal-network definition only assumes
            assumed = pb.direction_assumed - before_assumed
            incomplete = rule_partial or bool(missing) or bool(capped) or bool(assumed)
            if not (set(pb.families) & families) and evaluated == 0:
                state = "not_applicable_no_events" if not (rule_partial or capped) else "evaluated_partial"
            elif pb.kind == "aggregate" and matches:
                # aggregate rules may publish indicator events during consume(); those are matches
                state = "match_on_partial" if incomplete else "matched"
            elif pb.kind == "aggregate":
                state = "evaluated_partial" if incomplete else "evaluated_complete"
            elif matches:
                state = "match_on_partial" if incomplete else "matched"
            elif not pb.assures_negative:
                # script-text rules can show intent but never prove absence (spec section 1)
                state = "positive_only_partial" if incomplete else "positive_only"
            else:
                state = "evaluated_partial" if incomplete else "no_match_complete"
            reasons = list(base_reasons)
            if error_reason and (error_affected is ALL_FAMILIES or set(pb.families) & error_affected):
                reasons.append(error_reason)
            if missing:
                reasons.append(f"missing_required={missing}: records lacked a field this rule needs")
            detail = {"missing_required": missing, "reasons": reasons}
            if assumed:
                reasons.append(DIRECTION_ASSUMED_REASON)
                detail["direction_assumed"] = assumed
            if capped:
                # this partition's own refusals, per budget (the rule's totals are on its hunt-level coverage)
                refused = [f"state limit: {limit.text} ({limit.records - before_limits.get(name, 0)} record(s) not "
                           f"evaluated)" for name, limit in pb.limits.items()
                           if limit.records > before_limits.get(name, 0)]
                reasons.append(f"state_capped={capped}: records not evaluated because a state budget of this rule "
                               f"was full; " + "; ".join(refused))
                detail["state_capped"] = capped
            cells.append(self._cell(pb, target, pkey, state, len(matches), evaluated, detail))
        if staged or held or released:
            self._stage_put(list(staged.values()), raw_sources, held, released)
        staged.clear()
        # the event stage shares the stage volume: its growth counts toward the free-space reserve
        self.budget.check_free()
        # the partition's cells together: a crash before this leaves them all visibly `planned`
        self.repo.set_rule_cells(self.hunt_id, cells)
        self.repo.update_task(tid, "evaluated")

    def _count_boots(self, events) -> None:
        """Host-record events by where their boot id came from: a record, the boot-interval map, or nowhere."""
        counts = self.stats.setdefault("boot", {"recorded": 0, "from_interval": 0, "unknown": 0})
        for event in events:
            if event.family not in BOOT_FILL_FAMILIES or not event.host:
                continue
            boot = event.fields.get("host.boot.id")
            counts["unknown" if boot is None or boot.value in (None, "") else
                   "from_interval" if boot.origin.endswith(BOOT_INTERVAL_ORIGIN) else "recorded"] += 1

    def _boot_summary(self) -> None:
        """Why host records were left without a boot, and every range the sweep placed that records read later
        contradict (listed up to BOOT_LISTED; the boot-interval map record holds them all). A contradicted range
        makes the sweep partial: a boot-keyed join there may have been refused on a boot the whole map does not
        support."""
        boots = self.boots
        counts = self.stats.setdefault("boot", {"recorded": 0, "from_interval": 0, "unknown": 0})
        totals: dict[str, int] = {}
        for reasons in boots.unplaced.values():
            for reason, n in reasons.items():
                totals[reason] = totals.get(reason, 0) + n
        counts["unknown_reasons"] = dict(sorted(totals.items()))
        conflicts = boots.conflict_list()
        counts["sweep_conflicts"] = conflicts[:BOOT_LISTED]
        counts["sweep_conflicts_total"] = len(conflicts)
        # Each host with records left without a boot: why, and what on the host refuses placement.
        hosts = sorted(boots.unplaced, key=lambda host: (-sum(boots.unplaced[host].values()), host))
        listed = []
        for host in hosts[:BOOT_LISTED]:
            blind = boots.blind(host)
            listed.append({"host": host, "unplaced": dict(sorted(boots.unplaced[host].items())),
                           "blind": blind[:BOOT_BLIND_LISTED], "blind_total": len(blind),
                           "nameless_boundaries": len(boots.boundaries.get(host, ())),
                           "unclocked_records": boots.unclocked.get(host, 0),
                           "sweep_conflicts": len(boots.conflicts.get(host, ()))})
        counts["hosts"] = listed
        counts["hosts_total"] = len(hosts)
        if conflicts:
            hosts = sorted({item["host"] for item in conflicts})
            named = ", ".join(hosts[:10]) + (f" and {len(hosts) - 10} more" if len(hosts) > 10 else "")
            ranges = f"{len(conflicts)} range{'s' if len(conflicts) != 1 else ''}"
            where = f"{len(hosts)} host{'s' if len(hosts) != 1 else ''}"
            verb = "were" if len(conflicts) != 1 else "was"
            reason = (f"boot placement: {ranges} on {where} placed during the sweep {verb} contradicted by records "
                      f"read later ({named}); a boot-keyed join there may have been refused (see the hunt's "
                      f"boot-interval map)")
            self.partial_reasons.append(reason)
            # each rule that reads boot-placed families cannot claim a complete negative over those ranges
            self.repo.set_rule_cells(self.hunt_id, [
                self._cell(pb, "*", BOOT_PLACEMENT_PARTITION, "evaluated_partial", detail={"reasons": [reason]})
                for pb in self.pack if set(pb.families) & BOOT_FILL_FAMILIES])

    def _event_stage(self) -> EventStage:
        stage = getattr(self, "_stage", None)
        if stage is None:
            stage = self._stage = EventStage(self.stage_dir)
        return stage

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
        self.budget.finalizing = True           # finalize re-reads kept state: only the free-space reserve applies
        # Every partition has been read: record the whole map once, for expansion, the context pass and resume.
        self.repo.audit("system", BOOT_INTERVALS_AUDIT, self.hunt_id, self.boots.to_json())
        self._boot_summary()
        agg_raw = getattr(self, "_agg_raw", {})
        for pb in self.pack:
            if pb.kind != "aggregate":
                continue
            self.heartbeat()
            if pb.staged:
                stage = self._event_stage()
                pb.bind_loader(stage.load)
                pb.heartbeat = self.heartbeat
                ms = self._finalize_rule(pb)
                for m in ms:
                    self._publish(m, None, {**agg_raw, **stage.raw_sources(m.events)})
            else:
                ms = self._finalize_rule(pb)
                for m in ms:
                    self._publish(m, None, agg_raw)
            cells = [c for c in self.repo.rule_cells(self.hunt_id, rule_id=pb.id)
                     if c["target"] != "*" and c["state"] != "split"]
            any_partial = any(c["state"] in ("evaluated_partial", "executed_failed", "planned", "match_on_partial")
                              for c in cells)
            # A state budget reached at any point (in consume or at finalize) makes the whole-window result partial
            # and is named on the window cell.
            limits = pb.limit_reasons()
            any_partial = any_partial or bool(limits)
            evaluated = sum(c["evaluated"] or 0 for c in cells)
            consumed_matches = sum(c["matched"] or 0 for c in cells)
            matched_any = bool(ms) or consumed_matches > 0
            if not pb.assures_negative and not matched_any:
                # positive-only aggregate (argv/text-identified): never a complete negative
                state = "positive_only_partial" if (any_partial or not cells) else "positive_only"
            elif any_partial or not cells:
                state = "match_on_partial" if matched_any else "evaluated_partial"
            elif matched_any:
                state = "matched"
            elif evaluated == 0:
                # nothing of this rule's families was in scope: that is not a negative
                state = "not_applicable_no_events"
            else:
                state = "no_match_complete"
            reasons = (["no source partition of this rule was evaluated"] if not cells else
                       [WINDOW_ROLLUP_PARTIAL] if any_partial else [])
            if any(DIRECTION_ASSUMED_REASON in ((c["detail"] or {}).get("reasons") or []) for c in cells):
                reasons.append(DIRECTION_ASSUMED_REASON)
            reasons += limits
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, "*", "window", state,
                                    len(ms) + consumed_matches, evaluated, {"reasons": reasons})
            pb.release_state()
        agg_raw.clear()
        if self.budget.spent:
            self.partial_reasons.append(f"state budget: {self.budget.spent}")
            self.stats["state_budget"] = {"spent": self.budget.spent, "disk_bytes": self.budget.disk_used,
                                          "disk_total": self.budget.disk_total, "reserve": self.budget.reserve,
                                          "floor": self.budget.floor, "shared": self.budget.pool,
                                          "shared_used": self.budget.pool_used,
                                          "stores_without_new_keys": sorted(self.budget.full)}
        self.close_stage()

    @staticmethod
    def _finalize_rule(pb: Playbook) -> list[Match]:
        """A rule's finalize. When it needs disk the stage volume cannot give, the rule publishes what it can from
        state readable without writing (`finalize_fallback`: strong per-record items), and its window cell says
        which results were not computed (the hunt goes on)."""
        from romulus.detect.correlation import StageMissing
        try:
            return pb.finalize()
        except (StateExhausted, StageMissing, LookupError) as exc:
            pb.note_limit("state_disk", f"finalize stopped: {exc}; this rule's groupings were not computed, only "
                                        f"what it could publish without disk")
            try:
                return pb.finalize_fallback(str(exc))
            except (StateExhausted, StageMissing, LookupError):
                return []

    def close_stage(self) -> None:
        """Remove the disk stage (raw telemetry copies) and the playbooks' spills. Called by finalize and on every
        failure path."""
        stage = getattr(self, "_stage", None)
        if stage is not None:
            stage.close()
            self._stage = None
        for pb in self.pack:
            pb.close_spill()
