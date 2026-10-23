"""The deterministic sweep: plan partitions, stream every partition through normalization and all
playbooks, publish direct findings immediately, and keep an exact per-rule coverage ledger."""
from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from romulus.detect.base import Match, Playbook
from romulus.detect.registry import fresh_pack
from romulus.evidence.normalize import (
    BOOT_FILL_FAMILIES,
    BOOT_INTERVAL_ORIGIN,
    BootIntervals,
    normalize_hits,
)
from romulus.evidence.typed import TypedEvent, event_os_family
from romulus.evidence.windows import RecordIdContinuity
from romulus.evidence.windows_catalog import (
    WINDOWS_CHANNELS,
    WINDOWS_DATASET_FAMILIES,
    WINDOWS_HOST_DATASETS,
    collection_requirements,
    event_classes_for_families,
    lookup_event_class,
)
from romulus.hunt.publish import publish_match
from romulus.hunt.stage import EventStage
from romulus.site import SiteFacts, absent_site_facts
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
LINUX_HOST_DATASETS = ("linux.audit", "systemd.journal", "apache.access", "apache.error")
HOST_DATASETS = [*LINUX_HOST_DATASETS, *WINDOWS_HOST_DATASETS]
NET_FAMILIES = {"net_alert", "net_flow", "dns_query", "http_tx", "file_transfer", "tls_session", "ssh_session"}
# linux.audit now also yields `auth` (USER_LOGIN/USER_START), so an unparseable audit group may hide one.
# A login group that fails is tagged linux.audit.auth; it takes every record of its event, so it may also hide
# an exec, socket or file record of that event and carries the whole audit family set.
_AUDIT_ADMIN = {"account_change", "service_change", "audit_config", "system_state"}
LINUX_DATASET_FAMILIES = {
    "linux.audit": {"process_exec", "net_socket", "auth", "file_change"} | _AUDIT_ADMIN,
    "linux.audit.socket": {"net_socket"},
    "linux.audit.file": {"file_change"},
    "linux.audit.auth": {"process_exec", "net_socket", "auth", "file_change"} | _AUDIT_ADMIN,
    "linux.audit.admin": _AUDIT_ADMIN,
    "arkime.session": {"net_session"},
    "systemd.journal": {"auth", "privilege_use", "service_change"},
    "apache.access": {"http_access"},
    "apache.error": {"web_error"},
    **{f"suricata.eve.{event_type}": NET_FAMILIES for event_type in (
        "alert", "flow", "netflow", "dns", "http", "fileinfo", "tls", "ssh",
    )},
}
DATASET_FAMILIES = {**LINUX_DATASET_FAMILIES, **WINDOWS_DATASET_FAMILIES}
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
DEFAULT_WINDOWS_LIVENESS_TOLERANCE = timedelta(minutes=15)
MAX_SKIP_REASONS = 256
SKIP_REASON_OVERFLOW = "additional skip reasons omitted after bounded category limit"


def stored_boot_intervals(repo: Repo, hunt_id: str) -> BootIntervals:
    """The boot-interval map the hunt's sweep recorded; empty (it places nothing) when there is none."""
    row = repo.latest_audit(hunt_id, BOOT_INTERVALS_AUDIT) if hasattr(repo, "latest_audit") else None
    return BootIntervals.from_json((row or {}).get("detail") or {})


def plan_partitions(client: ElasticClient, target: str, contract: FieldContract, window: Window,
                    filters: list[Predicate], any_of: list[list[Predicate]] | None = None,
                    ) -> list[tuple[Window, int]]:
    """5-minute histogram with exact counts; merge consecutive buckets up to PARTITION_MAX_DOCS.
    A single bucket above the limit becomes its own partition and is split adaptively at run time."""
    h = execute(client, SearchIntent(kind="histogram", target=target, window=window, filters=filters,
                                     any_of=any_of or [],
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
                 heartbeat: Callable[[], None] | None = None, stage_dir=None, prefetch: bool | None = None,
                 site_facts: SiteFacts | None = None,
                 windows_liveness_tolerance: timedelta = DEFAULT_WINDOWS_LIVENESS_TOLERANCE):
        self.repo, self.client, self.hunt_id, self.window = repo, client, hunt_id, window
        # Fetch the next partition while this one is evaluated (the client's setting unless given). It changes
        # when a partition's records are read, never what is read or the order partitions are evaluated in.
        settings = getattr(client, "settings", None)
        self.prefetch = bool(getattr(settings, "sweep_prefetch", False)) if prefetch is None else prefetch
        self._next: tuple | None = None            # the partition after the current top-level one
        self._ahead: tuple[str, Future] | None = None
        self._pool: ThreadPoolExecutor | None = None
        self.contracts = contracts
        self.site_facts = site_facts or absent_site_facts()
        # Three 5-minute planning buckets tolerate normal low-volume jitter but expose material head/tail outages.
        self.windows_liveness_tolerance = windows_liveness_tolerance
        self._windows_inventory: dict[str, set[str]] = {}
        self._windows_inventory_reasons: dict[str, list[str]] = {}
        self._windows_record_ids = RecordIdContinuity()
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

    def _filters_for(self, target: str, contract: FieldContract | None = None) -> list[Predicate]:
        if contract is not None and contract.role == "host":
            if contract.os_family == "windows":
                return []
            datasets = LINUX_HOST_DATASETS
            # recorded so the report can list the target's other datasets as not assessed
            self.stats.setdefault("dataset_filter", {})[target] = list(datasets)
            return [Predicate(field="event.dataset", op="in", value=list(datasets))]
        return []

    def _any_of_for(self, target: str, contract: FieldContract | None = None) -> list[list[Predicate]]:
        """Select Windows event logs by dataset or native channel; Winlogbeat may omit event.dataset."""
        if contract is None or contract.role != "host" or contract.os_family != "windows":
            return []
        groups: list[list[Predicate]] = []
        if contract.supports("event.dataset", "in"):
            groups.append([Predicate(field="event.dataset", op="in", value=list(WINDOWS_HOST_DATASETS))])
        if contract.supports("event.channel", "in"):
            groups.append([Predicate(field="event.channel", op="in", value=list(WINDOWS_CHANNELS))])
        self.stats.setdefault("dataset_filter", {})[target] = list(WINDOWS_HOST_DATASETS)
        self.stats.setdefault("channel_filter", {})[target] = list(WINDOWS_CHANNELS)
        return groups

    def _prepare_windows_inventory(self, target: str, contract: FieldContract | None) -> None:
        if contract is None or contract.os_family != "windows" or target in self._windows_inventory:
            return
        required = ("event.channel", "event.provider", "event.code")
        if not all(contract.supports(field, "exists") for field in required):
            self._windows_inventory[target] = set()
            self._windows_inventory_reasons[target] = [
                "event class inventory unavailable: channel/provider/event id fields are not searchable"
            ]
            return
        outcome = execute(
            self.client,
            SearchIntent(
                kind="aggregate",
                target=target,
                window=self.window,
                filters=[Predicate(field=field, op="exists") for field in required],
                group_by=list(required),
                purpose="windows event class inventory",
            ),
            contract,
        )
        inventory = set()
        counts: dict[str, int] = {}
        classes_by_token = {}
        for bucket in outcome.buckets:
            key = bucket.get("key") or {}
            event_class = lookup_event_class(
                key.get("event.channel"), key.get("event.provider"), key.get("event.code")
            )
            if event_class is not None:
                inventory.add(event_class.token)
                counts[event_class.token] = counts.get(event_class.token, 0) + int(bucket.get("count") or 0)
                classes_by_token[event_class.token] = event_class
        reasons = []
        if outcome.completeness != Completeness.complete:
            reasons.append(
                "event class inventory incomplete: " + ", ".join(outcome.reasons or [outcome.error or "unknown"])
            )
        self._windows_inventory[target] = inventory
        self._windows_inventory_reasons[target] = reasons
        self.stats.setdefault("windows_inventory", {})[target] = {
            "cataloged_classes": len(inventory), "counts": dict(sorted(counts.items())), "reasons": reasons,
        }
        read_tokens = set()
        for playbook in self.pack:
            if "windows" not in playbook.os_families:
                continue
            if playbook.windows_event_classes:
                for channel, provider, event_id in playbook.windows_event_classes:
                    event_class = lookup_event_class(channel, provider, event_id)
                    if event_class is not None:
                        read_tokens.add(event_class.token)
            else:
                read_tokens.update(
                    event_class.token for event_class in event_classes_for_families(set(playbook.families))
                )
        unassessed = []
        for token in sorted(inventory - read_tokens):
            event_class = classes_by_token[token]
            unassessed.append({
                "channel": event_class.channel,
                "provider": event_class.provider,
                "event_id": event_class.event_id,
                "family": event_class.family,
                "records": counts[token],
            })
        if unassessed:
            self.stats.setdefault("windows_unassessed", {})[target] = unassessed

    @staticmethod
    def _windows_hosts(contract: FieldContract, records: list[dict]) -> tuple[str, ...]:
        hosts = {str(host).strip().rstrip(".").casefold() for host in contract.hosts if host}
        for record in records:
            winlog = (record.get("_source") or {}).get("winlog") or {}
            computer = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
            if computer:
                hosts.add(computer)
        return tuple(sorted(hosts))

    def _windows_rule_reasons(
        self,
        target: str,
        contract: FieldContract | None,
        playbook: Playbook,
        records: list[dict],
        gap_reasons: list[str],
        partition: Window | None = None,
    ) -> list[str]:
        if contract is None or contract.os_family != "windows" or "windows" not in playbook.os_families:
            return []
        catalog = event_classes_for_families(set(playbook.families))
        if not catalog:
            return []
        inventory = self._windows_inventory.get(target, set())
        reasons = list(self._windows_inventory_reasons.get(target, ()))
        if playbook.windows_event_classes:
            required = []
            for channel, provider, event_id in playbook.windows_event_classes:
                event_class = lookup_event_class(channel, provider, event_id)
                if event_class is None:
                    reasons.append(
                        f"event class declaration is not cataloged: {channel}|{provider}|{event_id}"
                    )
                else:
                    required.append(event_class)
        else:
            required = list(catalog)
        for event_class in required:
            if event_class.token not in inventory:
                reasons.append(
                    "event class absent from source inventory: "
                    f"{event_class.channel}|{event_class.provider}|{event_class.event_id}"
                )
        reasons.extend(gap_reasons)
        hosts = self._windows_hosts(contract, records)
        if not contract.host_inventory_complete:
            reasons.append("collection not attested: source host inventory truncated")
        if not hosts:
            reasons.append("collection not attested: source host inventory unavailable")
        observed_channels = {
            (
                str(((record.get("_source") or {}).get("winlog") or {}).get("computer_name") or "")
                .strip().rstrip(".").casefold(),
                str(((record.get("_source") or {}).get("winlog") or {}).get("channel") or "").casefold(),
            )
            for record in records
        }
        observed_times: dict[tuple[str, str], list[datetime]] = {}
        for record in records:
            source = record.get("_source") or {}
            winlog = source.get("winlog") or {}
            host = str(winlog.get("computer_name") or "").strip().rstrip(".").casefold()
            channel = str(winlog.get("channel") or "").casefold()
            raw_time = winlog.get("time_created") or source.get("@timestamp")
            try:
                when = datetime.fromisoformat(str(raw_time)).astimezone(UTC)
            except (TypeError, ValueError):
                continue
            observed_times.setdefault((host, channel), []).append(when)
        def summarize(label: str, affected: list[str], event_class) -> str | None:
            affected = sorted(set(affected))
            if not affected:
                return None
            if len(affected) == 1:
                return f"{label} on {affected[0]}"
            sample = ", ".join(affected[:10])
            token = f"{event_class.channel}|{event_class.provider}|{event_class.event_id}"
            return f"{label} on {len(affected):,} hosts [{token}] (sample: {sample})"

        for event_class in required:
            absent_hosts: list[str] = []
            late_start_hosts: list[str] = []
            early_stop_hosts: list[str] = []
            unattested_by_label: dict[str, list[str]] = {}
            single_edge_details: dict[tuple[str, str], str] = {}
            for host in hosts:
                channel_key = (host, event_class.channel.casefold())
                if channel_key not in observed_channels:
                    absent_hosts.append(host)
                elif partition is not None and observed_times.get(channel_key):
                    first, last = min(observed_times[channel_key]), max(observed_times[channel_key])
                    if first > partition.start + self.windows_liveness_tolerance:
                        late_start_hosts.append(host)
                        single_edge_details[("before", host)] = first.isoformat()
                    if last < partition.end - self.windows_liveness_tolerance:
                        early_stop_hosts.append(host)
                        single_edge_details[("after", host)] = last.isoformat()
                for fact, arguments, label in collection_requirements(event_class):
                    if not self.site_facts.attests(host, fact, **arguments):
                        unattested_by_label.setdefault(label, []).append(host)
            summarized = summarize(
                f"shipper gaps unresolved: no records on {event_class.channel} in partition",
                absent_hosts, event_class,
            )
            if summarized:
                reasons.append(summarized)
            for edge, affected in (("before", late_start_hosts), ("after", early_stop_hosts)):
                if len(set(affected)) == 1:
                    host = affected[0]
                    reasons.append(
                        f"no records from {host}/{event_class.channel} {edge} "
                        f"{single_edge_details[(edge, host)]}"
                    )
                else:
                    summarized = summarize(
                        f"no records from {event_class.channel} near partition {edge} edge",
                        affected, event_class,
                    )
                    if summarized:
                        reasons.append(summarized)
            for label, affected in unattested_by_label.items():
                summarized = summarize(f"collection not attested: {label}", affected, event_class)
                if summarized:
                    reasons.append(summarized)
        return sorted(set(reasons))

    @staticmethod
    def _unsupported_skips(skips: dict[str, int]) -> dict[str, int]:
        """Only unmodeled source formats poison rules; cataloged-source event classes are not-assessed data."""
        return {
            reason: count for reason, count in skips.items()
            if reason.startswith(("dataset:", "suricata event_type"))
        }

    @staticmethod
    def _bounded_counts(target: dict[str, int], additions: dict[str, int]) -> dict[str, str]:
        applied = {}
        for reason, count in additions.items():
            key = reason if reason in target or len(target) < MAX_SKIP_REASONS else SKIP_REASON_OVERFLOW
            target[key] = target.get(key, 0) + count
            applied[reason] = key
        return applied

    def _record_skips(self, target: str, skips: dict[str, int]) -> None:
        """Keep exact totals with a bounded number of telemetry-controlled reason strings, scoped by target."""
        global_keys = self._bounded_counts(self.stats["skips"], skips)
        windows_skips = {
            reason: count for reason, count in skips.items()
            if reason.startswith(("Windows event class", "duplicate Windows event copy"))
        }
        if windows_skips:
            by_target = self.stats.setdefault("skips_by_target", {}).setdefault(target, {})
            self._bounded_counts(by_target, windows_skips)
            scoped_global = self.stats.setdefault("skips_scoped_global", {})
            for reason, count in windows_skips.items():
                key = global_keys[reason]
                scoped_global[key] = scoped_global.get(key, 0) + count

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
        self._prepare_windows_inventory(target, contract)
        filters = self._filters_for(target, contract)
        any_of = self._any_of_for(target, contract)
        try:
            self.heartbeat()
            parts = plan_partitions(self.client, target, contract, self.window, filters, any_of)
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
                self._next = (target, contract, filters, any_of, *following) if following else None
                self.run_partition(target, contract, filters, w, est, any_of=any_of)
        finally:
            self._next = None
            self._stop_prefetch()

    @staticmethod
    def _raw_intent(target: str, filters: list[Predicate], w: Window, est: int,
                    any_of: list[list[Predicate]] | None = None) -> SearchIntent:
        cap = max(PARTITION_MAX_DOCS, int(est * 1.2) + 1000)
        return SearchIntent(kind="raw", target=target, window=w, filters=filters, any_of=any_of or [],
                            max_records=cap, purpose="sweep")

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
        target, contract, filters, any_of, w, est = self._next
        self._next = None
        if est > PARTITION_MAX_DOCS and (w.end - w.start) > MIN_SPLIT * 2:
            return                                   # it is split before anything is fetched
        intent = self._raw_intent(target, filters, w, est, any_of)
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

    def _count(self, target: str, contract: FieldContract, filters: list[Predicate], w: Window,
               any_of: list[list[Predicate]] | None = None) -> int | None:
        """The exact number of records in a window, or None when the source does not say exactly."""
        out = execute(self.client, SearchIntent(kind="histogram", target=target, window=w, filters=filters,
                                                any_of=any_of or [],
                                                interval_seconds=BUCKET_SECONDS, purpose="sweep count"), contract)
        if out.completeness == Completeness.complete and out.total_relation == "eq" and out.total is not None:
            return out.total
        return None

    def run_partition(self, target: str, contract: FieldContract, filters: list[Predicate], w: Window, est: int,
                      *, estimated: bool = False, any_of: list[list[Predicate]] | None = None):
        """Evaluate one partition. `est` is the histogram's exact count for a planned partition; for a half of a
        split one (`estimated`) it is only an estimate, so the half is counted before it is fetched."""
        self.heartbeat()
        splittable = (w.end - w.start) > MIN_SPLIT * 2
        if est > PARTITION_MAX_DOCS and splittable:
            # exact histogram count already exceeds the limit: subdivide before fetching anything
            a, b = self._split(target, w)
            self.run_partition(target, contract, filters, a, est // 2, estimated=True, any_of=any_of)
            self.run_partition(target, contract, filters, b, est - est // 2, estimated=True, any_of=any_of)
            return
        pkey = w.key()
        intent = self._raw_intent(target, filters, w, est, any_of)
        cap = intent.max_records
        tid = "t-" + digest({"h": self.hunt_id, "target": target, "w": pkey})[:20]
        self.repo.upsert_task(tid, self.hunt_id, "sweep", "sweep", intent.model_dump(mode="json"), tid)
        # No skip-on-resume: aggregate playbooks must consume every partition again or their
        # coverage would claim completeness over a subset. Writes are idempotent, so re-reading
        # is safe (attempts are counted and visible).
        self.repo.update_task(tid, "leased", attempt=True)
        mid = w.start + (w.end - w.start) / 2
        children = [f"{w.start.isoformat()}/{mid.isoformat()}", f"{mid.isoformat()}/{w.end.isoformat()}"]
        counted = self._count(target, contract, filters, w, any_of) if estimated and splittable else None
        if counted is not None and counted > fetch_limit(cap):
            # The fetch would stop at its cap and be split: split now, without reading records only to drop them.
            # The cap is the same, so the halves and their estimates are those a capped fetch would have given.
            self.heartbeat()
            self.repo.update_task(tid, "split", outcome={"completeness": Completeness.partial,
                                                         "reasons": [f"cap:{cap}<total:{counted}"], "total": counted,
                                                         "returned": 0, "counted": True, "children": children})
            a, b = self._split(target, w)
            self.run_partition(target, contract, filters, a, counted // 2, estimated=True, any_of=any_of)
            self.run_partition(target, contract, filters, b, counted // 2, estimated=True, any_of=any_of)
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
            self.run_partition(target, contract, filters, a, half, estimated=True, any_of=any_of)
            self.run_partition(target, contract, filters, b, half, estimated=True, any_of=any_of)
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
        raw_sources = {f"{r['_index']}/{r['_id']}": r["_source"] for r in out.records}
        duplicate_events = []
        if any(event.normalizer.startswith("windows-") for event in events):
            events, duplicate_events = self._event_stage().unique_windows(events)
        if duplicate_events:
            skips["duplicate typed event across source partitions"] = len(duplicate_events)
            self.repo.merge_evidence_raw(self.hunt_id, duplicate_events, raw_sources)
        self.stats["events"] += len(events)
        self._count_boots(events)
        self.stats["errors"] += len(errors)
        self._record_skips(target, skips)
        # records retrieved but of a dataset/event type no normalizer supports: we cannot say what
        # they contain, so no rule may claim a complete negative over this partition
        unsupported = self._unsupported_skips(skips)
        gap_reasons = []
        if contract is not None and contract.os_family == "windows":
            record_id = contract.spec("winlog.record_id")
            if record_id is None or record_id.type not in {"long", "integer", "short"}:
                gap_reasons = ["shipper gaps unresolved: winlog.record_id mapping is not numeric"]
            else:
                gap_reasons = self._windows_record_ids.observe(target, out.records)
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
        windows_gate_reasons: set[str] = set()
        # events the joining aggregates may cite later, by id: several playbooks stage the same events, and each
        # is serialized to the stage once per partition (the first staged copy of an id is kept)
        staged: dict[str, TypedEvent] = {}
        target_os = contract.os_family if contract is not None else "linux"
        for pb in self.pack:
            def in_os_scope(event: TypedEvent, os_families=pb.os_families) -> bool:
                os_family = event_os_family(event)
                return os_family == "unknown" or os_family in os_families

            relevant_events = [event for event in events if event.family in pb.families]
            target_applicable = (
                any(in_os_scope(event) for event in relevant_events) if relevant_events
                else target_os == "unknown" or target_os in pb.os_families
            )
            windows_reasons = self._windows_rule_reasons(
                target, contract, pb, out.records, gap_reasons, w,
            )
            windows_gate_reasons.update(windows_reasons)
            rule_partial = target_applicable and (
                affected is ALL_FAMILIES or bool(set(pb.families) & affected) or bool(windows_reasons)
            )
            before_eval, before_missing = pb.evaluated, pb.missing_required
            scoped_events = [
                event for event in events
                if in_os_scope(event)
            ]
            matches = pb.consume(scoped_events)
            for m in matches:
                self._publish(m, tid, raw_sources)
            if pb.staged:
                # joining aggregates: full events and their raw copies go to disk, not memory
                for event in pb.drain_staged():
                    staged.setdefault(event.id, event)
            elif pb.kind == "aggregate":
                # aggregates retain examples: stash raw copies of their retained events now
                self._retain_aggregate_raw(pb, raw_sources)
            evaluated = pb.evaluated - before_eval
            missing = pb.missing_required - before_missing
            if evaluated or matches:
                target_applicable = True
            if not target_applicable:
                state = "not_applicable_no_events"
            elif not (set(pb.families) & families) and evaluated == 0:
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
            reasons.extend(windows_reasons)
            if error_reason and (error_affected is ALL_FAMILIES or set(pb.families) & error_affected):
                reasons.append(error_reason)
            if missing:
                reasons.append(f"missing_required={missing}: records lacked a field this rule needs")
            cells.append(self._cell(pb, target, pkey, state, len(matches), evaluated,
                                    {"missing_required": missing, "reasons": reasons}))
        if windows_gate_reasons:
            self.partial_reasons.append(
                f"{target} {pkey}: " + "; ".join(sorted(windows_gate_reasons))
            )
        if any(pb.staged for pb in self.pack):
            self._event_stage().put(list(staged.values()), raw_sources)
        staged.clear()
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

    def _merge_staged_match_raw(self, match: Match) -> dict[str, dict]:
        """Reload a final match from the sweep stage so later source copies remain cited."""
        stage = self._event_stage()
        loaded = {event.id: event for event in stage.load([event.id for event in match.events])}
        match.events = [loaded.get(event.id, event) for event in match.events]
        return stage.raw_sources(match.events)

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
                self._publish(m, None, {**agg_raw, **self._merge_staged_match_raw(m)})
            cells = [c for c in self.repo.rule_cells(self.hunt_id, rule_id=pb.id)
                     if c["target"] != "*" and c["state"] != "split"]
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
        continuity = getattr(self, "_windows_record_ids", None)
        if continuity is not None:
            continuity.close()
            self._windows_record_ids = None
