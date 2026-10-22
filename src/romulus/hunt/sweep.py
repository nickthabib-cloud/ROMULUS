"""The deterministic sweep: plan partitions, stream every partition through normalization and all
playbooks, publish direct findings immediately, and keep an exact per-rule coverage ledger."""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from romulus.detect.base import Match, Playbook
from romulus.detect.registry import fresh_pack
from romulus.evidence.normalize import (
    BOOT_FILL_FAMILIES,
    BOOT_INTERVAL_ORIGIN,
    BootIntervals,
    normalize_hits,
)
from romulus.hunt.publish import publish_match
from romulus.hunt.stage import EventStage
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


def stored_boot_intervals(repo: Repo, hunt_id: str) -> BootIntervals:
    """The boot-interval map the hunt's sweep recorded; empty (it places nothing) when there is none."""
    row = repo.latest_audit(hunt_id, BOOT_INTERVALS_AUDIT) if hasattr(repo, "latest_audit") else None
    return BootIntervals.from_json((row or {}).get("detail") or {})


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
                 heartbeat: Callable[[], None] | None = None, stage_dir=None):
        self.repo, self.client, self.hunt_id, self.window = repo, client, hunt_id, window
        self.contracts = contracts
        self.on_candidate = on_candidate or (lambda c: None)
        self.heartbeat = heartbeat or (lambda: None)
        self.stage_dir = stage_dir
        self.pack: list[Playbook] = fresh_pack()
        self.partial_reasons: list[str] = []
        # Built as partitions are read, in time order per target: each batch's events are placed with what has
        # been observed so far. Expansion and the context pass use the whole map, recorded at finalize.
        self.boots = BootIntervals()
        self.stats = {"partitions": 0, "records": 0, "events": 0, "candidates": 0, "skips": {}, "errors": 0,
                      "boot": {"recorded": 0, "from_interval": 0, "unknown": 0}}

    # -------------------------------------------------------------------------------------
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
        for pb in self.pack:
            rule_partial = affected is ALL_FAMILIES or bool(set(pb.families) & affected)
            before_eval, before_missing = pb.evaluated, pb.missing_required
            matches = pb.consume(events)
            for m in matches:
                self._publish(m, tid, raw_sources)
            if pb.staged:
                # joining aggregates: full events and their raw copies go to disk, not memory
                self._event_stage().put(pb.drain_staged(), raw_sources)
            elif pb.kind == "aggregate":
                # aggregates retain examples: stash raw copies of their retained events now
                self._retain_aggregate_raw(pb, raw_sources)
            evaluated = pb.evaluated - before_eval
            missing = pb.missing_required - before_missing
            if not (set(pb.families) & families) and evaluated == 0:
                state = "not_applicable_no_events" if not rule_partial else "evaluated_partial"
            elif pb.kind == "aggregate" and matches:
                # aggregate rules may publish indicator events during consume(); those are matches
                state = "match_on_partial" if (rule_partial or missing) else "matched"
            elif pb.kind == "aggregate":
                state = "evaluated_partial" if (rule_partial or missing) else "evaluated_complete"
            elif matches:
                state = "match_on_partial" if (rule_partial or missing) else "matched"
            elif not pb.assures_negative:
                # script-text rules can show intent but never prove absence (spec section 1)
                state = "positive_only_partial" if (rule_partial or missing) else "positive_only"
            else:
                state = "evaluated_partial" if (rule_partial or missing) else "no_match_complete"
            reasons = list(base_reasons)
            if error_reason and (error_affected is ALL_FAMILIES or set(pb.families) & error_affected):
                reasons.append(error_reason)
            if missing:
                reasons.append(f"missing_required={missing}: records lacked a field this rule needs")
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, target, pkey, state, len(matches), evaluated,
                                    {"missing_required": missing, "reasons": reasons})
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
            self.partial_reasons.append(
                f"boot placement: {ranges} on {where} placed during the sweep {verb} contradicted by records read "
                f"later ({named}); a boot-keyed join there may have been refused (see the hunt's boot-interval map)")

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
                ms = pb.finalize()
                for m in ms:
                    self._publish(m, None, {**agg_raw, **stage.raw_sources(m.events)})
            else:
                ms = pb.finalize()
                for m in ms:
                    self._publish(m, None, agg_raw)
            cells = [c for c in self.repo.rule_cells(self.hunt_id)
                     if c["rule_id"] == pb.id and c["target"] != "*" and c["state"] != "split"]
            any_partial = any(c["state"] in ("evaluated_partial", "executed_failed", "planned", "match_on_partial")
                              for c in cells)
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
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, "*", "window", state,
                                    len(ms) + consumed_matches, evaluated, {"reasons": reasons})
            pb.release_state()
        agg_raw.clear()
        self.close_stage()

    def close_stage(self) -> None:
        """Remove the disk stage (raw telemetry copies). Called by finalize and on every failure path."""
        stage = getattr(self, "_stage", None)
        if stage is not None:
            stage.close()
            self._stage = None
