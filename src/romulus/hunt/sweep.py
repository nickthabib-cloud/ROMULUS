"""The deterministic sweep: plan partitions, stream every partition through normalization and all
playbooks, publish direct findings immediately, and keep an exact per-rule coverage ledger."""
from __future__ import annotations

import logging
import sqlite3
from collections import Counter
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from itertools import batched

from romulus.baseline.carry import HourParents
from romulus.baseline.playbook import BaselineCell, BaselinePlaybook
from romulus.baseline.reasons import summarize
from romulus.baseline.spec import KeyContext, exec_serial
from romulus.detect import netdef
from romulus.detect.base import Match, Playbook
from romulus.detect.bounded import StateBudget, StateExhausted, live_stores
from romulus.detect.host import bind_lineage_citation_loader
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON
from romulus.detect.observed import observation
from romulus.detect.registry import fresh_pack
from romulus.evidence.normalize import (
    BOOT_FILL_FAMILIES,
    BOOT_INTERVAL_ORIGIN,
    BootIntervals,
    normalize_hits,
)
from romulus.evidence.typed import TypedEvent
from romulus.evidence.windows import RecordIdContinuity, windows_record_signature
from romulus.evidence.windows_catalog import (
    COLLECTION_CHANGE_EVENTS,
    EVENT_CLASSES,
    WINDOWS_CHANNELS,
    WINDOWS_DATASET_FAMILIES,
    WINDOWS_HOST_DATASETS,
    collection_requirements,
    event_classes_for_families,
    lookup_event_class,
)
from romulus.evidence.windows_reassembly import SCRIPT_FINALIZE_BATCH_SIZE, ScriptBlockAssembler
from romulus.hunt.publish import LineageCitationFetcher, publish_match
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
MAX_WINDOWS_CONTINUITY_COLLISION_KEYS = 128
MAX_WINDOWS_CONTINUITY_COLLISION_RECORDS = 1_024
# Dedup-token rows of window material one hunt may keep (each about 800 bytes stored, with its key and indexes, so
# about 400 MB): only hours a cell shares with other cells keep tokens, so this bounds deduplicating specs' material
# by the flows of split hours, not of the window. Cells past it are never written as history.
BASELINE_TOKEN_ROWS_PER_HUNT = 500_000
# planned cells are written before any partition runs, this many partitions per transaction
PLANNED_CHUNK = 500
LINUX_HOST_DATASETS = ("linux.audit", "systemd.journal", "apache.access", "apache.error")
HOST_DATASETS = [*LINUX_HOST_DATASETS, *WINDOWS_HOST_DATASETS]
ZEEK_CONN_DATASETS = frozenset({"zeek.connection", "zeek.conn"})
ZEEK_ICMP_TRANSPORTS = ("icmp", "icmpv6", "ipv6-icmp")
NET_FAMILIES = {"net_alert", "net_flow", "dns_query", "http_tx", "file_transfer", "tls_session", "ssh_session"}
# linux.audit now also yields `auth` (USER_LOGIN/USER_START), so an unparseable audit group may hide one.
# A login group that fails is tagged linux.audit.auth; it takes every record of its event, so it may also hide
# an exec, socket or file record of that event and carries the whole audit family set.
_AUDIT_ADMIN = {"account_change", "service_change", "audit_config", "system_state"}
LINUX_DATASET_FAMILIES = {
    "linux.audit": {"process_exec", "net_socket", "auth", "file_change", "process_observed"} | _AUDIT_ADMIN,
    "linux.audit.socket": {"net_socket", "process_observed"},
    "linux.audit.file": {"file_change", "process_observed"},
    "linux.audit.observed": {"process_observed"},
    "linux.audit.auth": {"process_exec", "net_socket", "auth", "file_change", "process_observed"} | _AUDIT_ADMIN,
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
MAX_WINDOWS_UNCATALOGUED = 256


def _families_of(datasets) -> frozenset[str]:
    return frozenset().union(*(DATASET_FAMILIES.get(dataset, frozenset()) for dataset in datasets))


_WINDOWS_FAMILIES = frozenset().union(*WINDOWS_DATASET_FAMILIES.values())
_ROLE_FAMILIES = {
    "host": _families_of(HOST_DATASETS),
    "network": _families_of([*(name for name in DATASET_FAMILIES if name.startswith("suricata.eve.")),
                             "arkime.session"]),
}


def delivered_families(profile: dict | None, contract: FieldContract | None) -> frozenset[str] | None:
    """The event families the normalizer can produce from one target, or None when nothing says.

    Typed values come from the normalizer, not from the index mapping (audit execs live in `event.original`),
    so the answer follows the profile's datasets. An inventory that cannot be read in full falls back to every
    family of the target's role. Errs toward more families: a family wrongly named only costs an unresolved
    baseline, while one wrongly left out would leave that target's history unread.
    """
    role = (profile or {}).get("role") or (contract.role if contract is not None else None)
    if role is None:
        return None
    if profile is None or any(str(note).startswith("ds inventory truncated") for note in profile.get("notes") or []):
        return _ROLE_FAMILIES.get(role)
    if profile.get("kind") == "arkime_sessions":
        # Arkime sessions are recognized by shape; their dataset inventory lists protocols.
        return DATASET_FAMILIES["arkime.session"]
    datasets = list(profile.get("datasets") or {})
    families = set(_families_of(datasets))
    windows = profile.get("os_family") == "windows" or (contract is not None and contract.os_family == "windows")
    if windows and (not datasets or any(dataset not in DATASET_FAMILIES for dataset in datasets)):
        # Any Windows-shaped record is normalized, whatever dataset name the shipper gave it.
        families |= _WINDOWS_FAMILIES
    return frozenset(families)


def baseline_applicability(profiles: dict[str, dict], contracts: dict | None, targets, specs) -> dict[str, set[str]]:
    """The baseline specs each target can deliver: one rule for the window cells and the history read."""
    out: dict[str, set[str]] = {}
    for target in targets:
        families = delivered_families(profiles.get(target), (contracts or {}).get(target))
        out[target] = {spec.id for spec in specs if families is None or set(spec.families) & families}
    return out


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
        self._windows_read_tokens: dict[str, set[str]] = {}
        self._windows_selective: set[str] = set()
        self._windows_record_ids: RecordIdContinuity | None = None
        self._windows_scripts: ScriptBlockAssembler | None = None
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
        bind_lineage_citation_loader(self.pack, LineageCitationFetcher(client, contracts).load)
        for pb in self.pack:
            pb.spill_dir = stage_dir          # a playbook's on-disk join tables live beside the event stage
            pb.budget = self.budget
        self._has_windows = any(contract is not None and contract.os_family == "windows"
                                for contract in contracts.values())
        # one guaranteed floor per live store of the pack (a store shared by several rules counts once), and one for
        # the event stage, which holds the citations of every rule. Windows hunts add independent floors for their
        # id-only delivery guard and continuity state, so event volume cannot take a detector store's floor.
        self.budget.plan(live_stores(self.pack) + 1 + (3 if self._has_windows else 0))
        self._stage_account = self.budget.account("event_stage")
        self._windows_seen_account = self.budget.account("windows_seen") if self._has_windows else None
        self._windows_continuity_account = (
            self.budget.account("windows_continuity") if self._has_windows else None
        )
        self._windows_scripts_account = self.budget.account("windows_scripts") if self._has_windows else None
        self._stage_size = 0
        self._profiles: dict[str, dict] | None = None
        # dedup-token rows of window material this hunt keeps, read from the store on first use (resume)
        self._baseline_token_rows: int | None = None
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
        self._charge_stage(stage)

    def _record_playbook_batch(
        self,
        pb: Playbook,
        matches: list[Match],
        raw_sources: dict[str, dict],
        task_id: str | None,
        staged: dict[str, TypedEvent],
        held: list[tuple[str, TypedEvent]],
        released: list[tuple[str, list[str]]],
    ) -> None:
        """Publish one consumed batch and retain everything its playbook may cite at finalize."""
        for match in matches:
            self._publish(
                match,
                task_id,
                self._sources_for(match, raw_sources) if pb.staged else raw_sources,
            )
        if pb.staged:
            # Joining aggregates keep full events and raw copies on disk, not in memory. Below the stage
            # volume's reserve the stage takes only strong rules' citations; another rule's held examples are
            # then not loadable, and its finalize says so.
            drained = pb.drain_staged()
            held_ids, released_ids = pb.drain_bounds()
            if released_ids:
                released.append((pb.id, released_ids))
            if drained and self.budget.hard and pb.state_slice != "strong":
                pb.note_limit(
                    "stage",
                    f"the event stage took no new citation of this rule ({self.budget.hard}); "
                    "its findings that cite them are not computed",
                )
                return
            # An event returned more often than it is held is also staged to be kept.
            holds = Counter(held_ids)
            copies = Counter(event.id for event in drained)
            for event in drained:
                if copies[event.id] > holds[event.id]:
                    staged.setdefault(event.id, event)
            for event in {event.id: event for event in drained if holds[event.id]}.values():
                held.extend([(pb.id, event)] * holds[event.id])
        elif pb.kind == "aggregate":
            # Aggregates retain examples: stash raw copies of their retained events now.
            self._retain_aggregate_raw(pb, raw_sources)

    def _charge_stage(self, stage: EventStage) -> None:
        """Charge the stage file's growth beyond the most it has held to the event stage's account."""
        size = stage.db.execute("PRAGMA page_count").fetchone()[0] * stage.db.execute("PRAGMA page_size").fetchone()[0]
        if size > self._stage_size:
            self.budget.charge(self._stage_account, size - self._stage_size)
            self._stage_size = size

    def _publish(self, m: Match, task_id: str | None, raw_sources: dict[str, dict]):
        playbook = next(playbook for playbook in self.pack if playbook.id == m.playbook_id)
        if m.raw_copies:
            raw_sources = {**m.raw_copies, **raw_sources}      # records the rule kept for citation itself
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
        """Select only normalized source shapes while preserving each target's other known datasets."""
        if contract is not None and contract.role == "network":
            if self._profiles is None:
                self._profiles = self.repo.source_profiles(self.hunt_id)
            profile = self._profiles.get(target) or {}
            datasets = sorted(profile.get("datasets") or {})
            zeek = [dataset for dataset in datasets if dataset in ZEEK_CONN_DATASETS]
            if (zeek and not any(str(note).startswith("ds inventory truncated")
                                 for note in profile.get("notes") or [])
                    and contract.supports("event.dataset", "in")
                    and contract.supports("event.dataset", "missing")
                    and contract.supports("network.transport", "in")
                    and contract.supports("network.transport", "missing")):
                groups = []
                others = [dataset for dataset in datasets if dataset not in ZEEK_CONN_DATASETS]
                if others:
                    groups.append([Predicate(field="event.dataset", op="in", value=others)])
                groups.append([
                    Predicate(field="event.dataset", op="in", value=zeek),
                    Predicate(field="network.transport", op="in", value=list(ZEEK_ICMP_TRANSPORTS)),
                ])
                # Some Zeek shippers leave ECS network.transport unset while conn.proto still records ICMP.
                # Fetch those records for local normalization instead of treating their absence as non-ICMP.
                groups.append([
                    Predicate(field="event.dataset", op="in", value=zeek),
                    Predicate(field="network.transport", op="missing"),
                ])
                # A missing dataset cannot be assigned to an inventoried class by the source query. Retrieve it
                # so the normalizer's unsupported-record accounting makes every affected coverage cell partial.
                groups.append([Predicate(field="event.dataset", op="missing")])
                self.stats.setdefault("dataset_filter", {})[target] = others
                self.stats.setdefault("zeek_transport_filter", {})[target] = list(ZEEK_ICMP_TRANSPORTS)
                return groups
            return []
        # Winlogbeat may omit event.dataset, so Windows also selects by native channel.
        if contract is None or contract.role != "host" or contract.os_family != "windows":
            return []
        read_tokens = getattr(self, "_windows_read_tokens", {}).get(target)
        if read_tokens is not None and all(contract.supports(field, "eq") for field in (
                "event.channel", "event.provider", "event.code")):
            control_tokens = {
                event.token for event in EVENT_CLASSES
                if event.key in COLLECTION_CHANGE_EVENTS
            }
            selected = [event for event in EVENT_CLASSES if event.token in read_tokens | control_tokens]
            if selected:
                self._windows_selective.add(target)
                self.stats.setdefault("windows_class_filter", {})[target] = [event.token for event in selected]
                return [[
                    Predicate(field="event.channel", op="eq", value=event.channel),
                    Predicate(field="event.provider", op="eq", value=event.provider),
                    Predicate(field="event.code", op="eq", value=event.event_id),
                ] for event in selected]
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
        unavailable = [
            field for field in required
            if (spec := contract.spec(field)) is None or not spec.aggregatable
        ]
        marker_groups = [
            [Predicate(field=field, op="exists")]
            for field in (*required, "host.name", "winlog.record_id")
            if contract.supports(field, "exists")
        ]
        if contract.supports("event.dataset", "in"):
            marker_groups.append([
                Predicate(field="event.dataset", op="in", value=list(WINDOWS_HOST_DATASETS))
            ])
        if unavailable or not marker_groups:
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
                any_of=marker_groups,
                group_by=list(required),
                purpose="windows event class inventory",
            ),
            contract,
        )
        inventory = set()
        counts: dict[str, int] = {}
        classes_by_token = {}
        uncatalogued: list[dict] = []
        uncatalogued_total = 0
        uncatalogued_overflow_classes = 0
        uncatalogued_overflow_records = 0
        malformed_identity_buckets = 0
        malformed_identity_records = 0
        for bucket in outcome.buckets:
            key = bucket.get("key") or {}
            count = int(bucket.get("count") or 0)
            raw_channel = key.get("event.channel")
            raw_provider = key.get("event.provider")
            raw_event_id = key.get("event.code")
            malformed_identity = (
                not isinstance(raw_channel, str)
                or not raw_channel.strip()
                or not isinstance(raw_provider, str)
                or not raw_provider.strip()
                or isinstance(raw_event_id, bool)
            )
            if not malformed_identity:
                try:
                    int(raw_event_id)
                except (TypeError, ValueError):
                    malformed_identity = True
            if malformed_identity:
                malformed_identity_buckets += 1
                malformed_identity_records += count
            event_class = (
                None if malformed_identity
                else lookup_event_class(raw_channel, raw_provider, raw_event_id)
            )
            if event_class is not None:
                inventory.add(event_class.token)
                counts[event_class.token] = counts.get(event_class.token, 0) + count
                classes_by_token[event_class.token] = event_class
                continue
            uncatalogued_total += 1
            if len(uncatalogued) >= MAX_WINDOWS_UNCATALOGUED:
                uncatalogued_overflow_classes += 1
                uncatalogued_overflow_records += count
                continue
            try:
                shown_event_id = int(raw_event_id)
            except (TypeError, ValueError):
                shown_event_id = str(raw_event_id or "<missing>")[:80]
            uncatalogued.append({
                "channel": str(key.get("event.channel") or "<missing>")[:200],
                "provider": str(key.get("event.provider") or "<missing>")[:200],
                "event_id": shown_event_id,
                "records": count,
                "uncatalogued": True,
            })
        reasons = []
        if malformed_identity_records:
            reasons.append(
                "event class inventory incomplete: "
                f"{malformed_identity_records:,} Windows record(s) have missing or invalid "
                "channel/provider/event id across "
                f"{malformed_identity_buckets:,} bucket(s)"
            )
        if outcome.completeness != Completeness.complete:
            reasons.append(
                "event class inventory incomplete: " + ", ".join(outcome.reasons or [outcome.error or "unknown"])
            )
        self._windows_inventory[target] = inventory
        self._windows_inventory_reasons[target] = reasons
        self.stats.setdefault("windows_inventory", {})[target] = {
            "cataloged_classes": len(inventory), "uncatalogued_classes": uncatalogued_total,
            "counts": dict(sorted(counts.items())), "reasons": reasons,
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
        self._windows_read_tokens[target] = read_tokens
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
        unassessed.extend(uncatalogued)
        if uncatalogued_overflow_classes:
            unassessed.append({
                "overflow": True,
                "uncatalogued": True,
                "classes": uncatalogued_overflow_classes,
                "records": uncatalogued_overflow_records,
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

    def _selective_windows_continuity(
        self,
        target: str,
        contract: FieldContract,
        partition: Window,
    ) -> tuple[dict[tuple[str, str], tuple[datetime, datetime]], list[str]]:
        """Read only host/channel/id/time metadata for all Windows records in one selective partition."""
        group_by = ("@timestamp", "host.name", "event.channel", "winlog.record_id")
        unavailable = [
            field for field in group_by
            if (spec := contract.spec(field)) is None or not spec.aggregatable
        ]
        if unavailable or not contract.supports("event.channel", "exists"):
            missing = ", ".join(unavailable or ["event.channel exists query"])
            return {}, [f"shipper gaps unresolved: continuity metadata unavailable for {missing}"]
        outcome = execute(
            self.client,
            SearchIntent(
                kind="aggregate",
                target=target,
                window=partition,
                filters=[Predicate(field="event.channel", op="exists")],
                group_by=list(group_by),
                max_records=PARTITION_MAX_DOCS,
                purpose="windows continuity metadata",
            ),
            contract,
        )
        stats = self.stats.setdefault("windows_continuity", {}).setdefault(target, {
            "mode": "metadata_aggregate", "partitions": 0, "buckets": 0, "partial_partitions": 0,
        })
        stats["partitions"] += 1
        stats["buckets"] += len(outcome.buckets)
        reasons: list[str] = []
        if outcome.completeness != Completeness.complete:
            stats["partial_partitions"] += 1
            detail = ", ".join(outcome.reasons or [outcome.error or "unknown source failure"])
            reasons.append(f"shipper gaps unresolved: continuity metadata incomplete: {detail}")
            return {}, reasons

        observed: dict[tuple[str, str], tuple[datetime, datetime]] = {}
        reconstructed: list[tuple[datetime, str, str, int, int]] = []
        collisions: list[dict] = []
        malformed_groups = 0
        malformed_times = 0
        malformed_ids = 0
        for ordinal, bucket in enumerate(outcome.buckets):
            key = bucket.get("key") or {}
            native_host = str(key.get("host.name") or "").strip().rstrip(".")
            host = native_host.casefold()
            channel = str(key.get("event.channel") or "").strip()
            if not host or not channel:
                malformed_groups += 1
                continue
            first = last = None
            try:
                first = datetime.fromisoformat(str(bucket.get("first"))).astimezone(UTC)
                last = datetime.fromisoformat(str(bucket.get("last"))).astimezone(UTC)
            except (TypeError, ValueError):
                malformed_times += 1
                continue
            raw_record_id = key.get("winlog.record_id")
            if isinstance(raw_record_id, bool):
                malformed_ids += 1
                continue
            try:
                record_id = int(raw_record_id)
            except (TypeError, ValueError):
                malformed_ids += 1
                continue
            if first is not None and last is not None:
                group = (host, channel.casefold())
                prior = observed.get(group)
                observed[group] = (
                    first if prior is None else min(prior[0], first),
                    last if prior is None else max(prior[1], last),
                )
            count = int(bucket.get("count") or 0)
            if count > 1:
                collisions.append({
                    "when": first,
                    "native_host": native_host,
                    "host": host,
                    "channel": channel,
                    "record_id": record_id,
                    "count": count,
                })
            else:
                reconstructed.append((first, host, channel, record_id, ordinal))
        if malformed_groups:
            reasons.append(
                f"shipper gaps unresolved: {malformed_groups} continuity metadata bucket(s) lack host or channel"
            )
        if malformed_times:
            reasons.append(
                f"shipper gaps unresolved: {malformed_times} continuity metadata bucket(s) lack valid timestamps"
            )
        if malformed_ids:
            reasons.append(
                f"shipper gaps unresolved: {malformed_ids} continuity metadata bucket(s) lack numeric record_id"
            )
        if reasons:
            return {}, reasons

        collision_records: list[dict] = []
        if collisions:
            followup_ops = (
                ("host.name", "eq"), ("event.channel", "eq"), ("winlog.record_id", "eq"),
            )
            unsupported = [
                f"{field} {op}" for field, op in followup_ops if not contract.supports(field, op)
            ]
            expected_records = sum(item["count"] for item in collisions)
            if unsupported:
                stats["partial_partitions"] += 1
                reasons.append(
                    "shipper gaps unresolved: continuity collision records unavailable for "
                    + ", ".join(unsupported)
                )
                return {}, reasons
            if len(collisions) > MAX_WINDOWS_CONTINUITY_COLLISION_KEYS:
                stats["partial_partitions"] += 1
                reasons.append(
                    "shipper gaps unresolved: continuity collision key cap exceeded: "
                    f"{len(collisions):,}>{MAX_WINDOWS_CONTINUITY_COLLISION_KEYS:,}"
                )
                return {}, reasons
            if expected_records > MAX_WINDOWS_CONTINUITY_COLLISION_RECORDS:
                stats["partial_partitions"] += 1
                reasons.append(
                    "shipper gaps unresolved: continuity collision record cap exceeded: "
                    f"{expected_records:,}>{MAX_WINDOWS_CONTINUITY_COLLISION_RECORDS:,}"
                )
                return {}, reasons

            by_time: dict[datetime, list[dict]] = {}
            for item in collisions:
                by_time.setdefault(item["when"], []).append(item)
            fetched_records: list[dict] = []
            for when, items in sorted(by_time.items()):
                followup = execute(
                    self.client,
                    SearchIntent(
                        kind="raw",
                        target=target,
                        window=Window(start=when, end=when + timedelta(microseconds=1)),
                        any_of=[[
                            Predicate(field="host.name", op="eq", value=item["native_host"]),
                            Predicate(field="event.channel", op="eq", value=item["channel"]),
                            Predicate(field="winlog.record_id", op="eq", value=item["record_id"]),
                        ] for item in items],
                        max_records=sum(item["count"] for item in items),
                        purpose="windows continuity collision signatures",
                    ),
                    contract,
                )
                stats["collision_followups"] = stats.get("collision_followups", 0) + 1
                if followup.completeness != Completeness.complete:
                    stats["partial_partitions"] += 1
                    detail = ", ".join(followup.reasons or [followup.error or "unknown source failure"])
                    reasons.append(
                        f"shipper gaps unresolved: continuity collision records incomplete: {detail}"
                    )
                    return {}, reasons
                fetched_records.extend(followup.records)

            expected: dict[tuple[datetime, str, str, int], int] = {}
            for item in collisions:
                key = (item["when"], item["host"], item["channel"].casefold(), item["record_id"])
                expected[key] = expected.get(key, 0) + item["count"]
            fetched: dict[tuple[datetime, str, str, int], list[dict]] = {
                key: [] for key in expected
            }
            for record in fetched_records:
                source = record.get("_source") or {}
                winlog = source.get("winlog") or {}
                raw_id = winlog.get("record_id")
                if isinstance(raw_id, bool):
                    continue
                try:
                    record_id = int(raw_id)
                    when = datetime.fromisoformat(str(source.get("@timestamp"))).astimezone(UTC)
                except (TypeError, ValueError):
                    continue
                key = (
                    when,
                    str(winlog.get("computer_name") or "").strip().rstrip(".").casefold(),
                    str(winlog.get("channel") or "").strip().casefold(),
                    record_id,
                )
                if key in fetched:
                    fetched[key].append(record)

            mismatched = [
                (key, expected[key], len(records))
                for key, records in fetched.items()
                if len(records) != expected[key]
            ]
            if mismatched:
                stats["partial_partitions"] += 1
                expected_count = sum(item[1] for item in mismatched)
                fetched_count = sum(item[2] for item in mismatched)
                reasons.append(
                    "shipper gaps unresolved: continuity collision records incomplete: "
                    f"expected {expected_count:,} exact record(s), fetched {fetched_count:,}"
                )
                return {}, reasons
            for key in sorted(fetched):
                copies = fetched[key]
                stats["collision_signature_conflicts"] = (
                    stats.get("collision_signature_conflicts", 0)
                    + int(len({windows_record_signature(record) for record in copies}) > 1)
                )
                for record in copies:
                    source = record.get("_source") or {}
                    agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
                    collision_records.append({
                        **record,
                        "_source": {**source, "agent": {**agent, "type": "winlogbeat"}},
                    })

        records = [{
                "_index": target,
                "_id": f"continuity-{ordinal}",
                "_source": {
                    "@timestamp": first.isoformat() if first is not None else "",
                    "agent": {"type": "winlogbeat"},
                    "winlog": {
                        "computer_name": host,
                        "channel": channel,
                        "record_id": record_id,
                        "time_created": first.isoformat() if first is not None else "",
                    },
                },
            }
            for first, host, channel, record_id, ordinal in sorted(reconstructed)
        ]
        records.extend(collision_records)

        def continuity_order(record: dict) -> tuple:
            source = record.get("_source") or {}
            winlog = source.get("winlog") or {}
            raw_time = winlog.get("time_created") or source.get("@timestamp")
            return (
                datetime.fromisoformat(str(raw_time)).astimezone(UTC),
                str(winlog.get("computer_name") or "").casefold(),
                str(winlog.get("channel") or "").casefold(),
                int(winlog.get("record_id")),
                windows_record_signature(record),
                str(record.get("_index") or ""),
                str(record.get("_id") or ""),
            )

        records.sort(key=continuity_order)
        if records:
            reasons.extend(self._windows_continuity().observe(
                target, records, liveness_tolerance=self.windows_liveness_tolerance,
            ))
        return observed, reasons

    def _windows_rule_reasons(
        self,
        target: str,
        contract: FieldContract | None,
        playbook: Playbook,
        records: list[dict],
        gap_reasons: list[str],
        partition: Window | None = None,
        continuity_times: dict[tuple[str, str], tuple[datetime, datetime]] | None = None,
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
        hosts = set(self._windows_hosts(contract, records))
        if continuity_times is not None:
            hosts.update(host for host, _channel in continuity_times)
        hosts = tuple(sorted(hosts))
        if not contract.host_inventory_complete:
            reasons.append("collection not attested: source host inventory truncated")
        if not hosts:
            reasons.append("collection not attested: source host inventory unavailable")
        if continuity_times is None:
            observed_channels = {
                (
                    str(((record.get("_source") or {}).get("winlog") or {}).get("computer_name") or "")
                    .strip().rstrip(".").casefold(),
                    str(((record.get("_source") or {}).get("winlog") or {}).get("channel") or "").casefold(),
                )
                for record in records
            }
            observed_times: dict[tuple[str, str], tuple[datetime, datetime]] = {}
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
                key = (host, channel)
                prior = observed_times.get(key)
                observed_times[key] = (
                    (when, when) if prior is None else (min(prior[0], when), max(prior[1], when))
                )
        else:
            observed_channels = set(continuity_times)
            observed_times = dict(continuity_times)
        collection_changes, cross_channel_collection_changes = self._windows_collection_changes(records)

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
                reasons.extend(sorted(cross_channel_collection_changes.get(host, ())))
                reasons.extend(sorted(collection_changes.get(channel_key, ())))
                if channel_key not in observed_channels:
                    absent_hosts.append(host)
                elif partition is not None and observed_times.get(channel_key):
                    first, last = observed_times[channel_key]
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
    def _windows_collection_changes(
        records: list[dict],
    ) -> tuple[dict[tuple[str, str], set[str]], dict[str, set[str]]]:
        """Classify collection breaks by native host and either one channel or every channel on that host."""
        collection_changes: dict[tuple[str, str], set[str]] = {}
        cross_channel_collection_changes: dict[str, set[str]] = {}
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
            try:
                event_id = int(winlog.get("event_id"))
            except (TypeError, ValueError):
                continue
            provider = str(winlog.get("provider_name") or "").strip()
            change = COLLECTION_CHANGE_EVENTS.get((channel, provider.casefold(), event_id))
            if (change and provider.casefold() == "microsoft-windows-sysmon" and event_id == 4
                    and str((winlog.get("event_data") or {}).get("State") or "").casefold() == "started"):
                change = None
            if change and host:
                reason = (
                    f"collection changed on {host} at {when.isoformat()}: "
                    f"{winlog.get('channel')}|{provider}|{event_id} ({change})"
                )
                # Security/audit-service controls invalidate every Windows channel; provider-operational
                # controls govern only the channel that emitted them.
                if event_id in {104, 1102, 4719, 6006}:
                    cross_channel_collection_changes.setdefault(host, set()).add(reason)
                else:
                    collection_changes.setdefault((host, channel), set()).add(reason)
        return collection_changes, cross_channel_collection_changes

    @staticmethod
    def _unsupported_skips(skips: dict[str, int]) -> dict[str, int]:
        """Only unmodeled source formats poison rules; cataloged-source event classes are not-assessed data."""
        return {
            reason: count for reason, count in skips.items()
            if reason.startswith(("dataset:", "suricata event_type", "zeek non-ICMP connection"))
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
        self.repo.set_rule_cells(self.hunt_id, [
            self._cell(pb, target, pkey, state, detail=detail)
            for pb in self.pack
            if not (isinstance(pb, BaselinePlaybook)
                    and self.repo.baseline_window_cell_done(self.hunt_id, pb.id, pb.version, target, pkey))
        ])

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
            self.repo.set_rule_cells(self.hunt_id, [
                self._cell(pb, target, w.key(), "planned")
                for w, _est in parts[start:start + PLANNED_CHUNK]
                for pb in self.pack
                if not (isinstance(pb, BaselinePlaybook)
                        and self.repo.baseline_window_cell_done(
                            self.hunt_id, pb.id, pb.version, target, w.key()))
            ])
        try:
            for index, (w, est) in enumerate(parts):
                following = parts[index + 1] if index + 1 < len(parts) else None
                self._next = (target, contract, filters, any_of, *following) if following else None
                self.run_partition(target, contract, filters, w, est, any_of=any_of)
            self._finalize_baseline_target(target)
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
        windows_state_reasons: list[str] = []
        script_reassembly_reasons: list[str] = []
        script_metadata_reasons: list[str] = []
        if any(event.normalizer.startswith("windows-") for event in events):
            stage = self._event_stage()
            events, duplicate_events = stage.unique_windows(events)
            if stage.windows_refused:
                windows_state_reasons.append(
                    f"Windows event dedup state refused {stage.windows_refused} event id(s): "
                    f"{stage.windows_refusal_reason}; those events were evaluated, but a shipper copy of one in a "
                    f"later partition is evaluated again, so counts over them may include duplicates"
                )
        if duplicate_events:
            skips["duplicate typed event across source partitions"] = len(duplicate_events)
            self.repo.merge_evidence_raw(self.hunt_id, duplicate_events, raw_sources)
        if any(event.family == "script_block" for event in events):
            assembler = self._windows_script_blocks()
            events = assembler.consume(events, raw_sources)
            raw_sources.update(assembler.sources_for(events))
            script_reassembly_reasons.extend(assembler.partial_reasons)
            incomplete_metadata = sum(
                any("script block part metadata is incomplete or invalid" in caveat
                    for caveat in event.caveats)
                for event in events
            )
            if incomplete_metadata:
                script_metadata_reasons.append(
                    "PowerShell script-block part metadata incomplete or invalid for "
                    f"{incomplete_metadata} event(s)"
                )
        self.stats["events"] += len(events)
        self._count_boots(events)
        self.stats["errors"] += len(errors)
        self._record_skips(target, skips)
        # records retrieved but of a dataset/event type no normalizer supports: we cannot say what
        # they contain, so no rule may claim a complete negative over this partition
        unsupported = self._unsupported_skips(skips)
        gap_reasons = list(windows_state_reasons)
        continuity_times = None
        if contract is not None and contract.os_family == "windows":
            record_id = contract.spec("winlog.record_id")
            if record_id is None or record_id.type not in {"long", "integer", "short"}:
                gap_reasons.append("shipper gaps unresolved: winlog.record_id mapping is not numeric")
            elif target not in self._windows_selective:
                gap_reasons.extend(self._windows_continuity().observe(
                    target, out.records, liveness_tolerance=self.windows_liveness_tolerance,
                ))
            else:
                continuity_times, continuity_reasons = self._selective_windows_continuity(
                    target, contract, w,
                )
                gap_reasons.extend(continuity_reasons)
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
        held: list[tuple[str, TypedEvent]] = []          # (playbook, event) holds of interval bounds
        released: list[tuple[str, list[str]]] = []       # (playbook, ids) holds the playbooks let go
        target_os = contract.os_family if contract is not None else "linux"
        for pb in self.pack:
            # families a rule reads only as context (its lineage) do not make a partition an evaluation of it
            evaluated_families = set(pb.families) - set(pb.context_families)
            relevant_events = [event for event in events if event.family in evaluated_families]
            target_fallback = not relevant_events and (
                target_os == "unknown" or target_os in pb.os_families
            )
            windows_reasons = self._windows_rule_reasons(
                target, contract, pb, out.records, gap_reasons, w, continuity_times,
            )
            if (script_metadata_reasons and contract.os_family == "windows"
                    and "script_block" in pb.families):
                windows_reasons.extend(script_metadata_reasons)
            if (script_reassembly_reasons and contract.os_family == "windows"
                    and "script_block" in pb.families):
                windows_reasons.extend(script_reassembly_reasons)
            windows_gate_reasons.update(windows_reasons)
            rule_partial = (affected is ALL_FAMILIES or bool(set(pb.families) & affected)
                            or bool(windows_reasons))
            if isinstance(pb, BaselinePlaybook):
                if self.repo.baseline_window_cell_done(
                        self.hunt_id, pb.id, pb.version, target, pkey):
                    continue
                ordered = sorted(pb.scope_partition(events), key=lambda item: (
                    item.ts, -1 if exec_serial(item) is None else exec_serial(item), item.id,
                ))
                # Unknown or malformed records can hide behavior, so they make retrieval partial, but they do not
                # attest that this source delivers the baseline family. Keep applicability profile/event based and
                # carry the uncertainty through retrieval_complete instead.
                target_applicable = (
                    bool(ordered)
                    or error_affected is ALL_FAMILIES
                    or self._baseline_target_applicable(target, pb)
                )
                reasons = list(base_reasons)
                reasons.extend(windows_reasons)
                if error_reason and (error_affected is ALL_FAMILIES or set(pb.families) & error_affected):
                    reasons.append(error_reason)
                if pb.id == "bl.exec_pair":
                    carry_events = sorted(
                        (event for event in events
                         if event.family == "process_exec" or observation(event) is not None),
                        key=lambda item: (
                            item.ts, -1 if exec_serial(item) is None else exec_serial(item), item.id,
                        ),
                    )
                    parents = HourParents()
                    for event in ordered:
                        parents.add(event)
                    pb.begin_cell(pkey, (w.start, w.end), KeyContext(pid_table=parents))
                    before_eval = pb.evaluated
                    pb.consume_scoped_partition(ordered)
                    result = pb.finish_cell()
                    reasons.extend(result.reasons)
                    evaluated = pb.evaluated - before_eval
                    # A complete hour without execs is staged like any other, so the carry's ledger counts it as
                    # observed; an inapplicable or incomplete one is final here and never joins that ledger.
                    if not ordered and (not target_applicable or rule_partial or reasons):
                        state = ("evaluated_partial" if target_applicable and (rule_partial or reasons)
                                 else "not_applicable_no_events")
                        detail = {"reasons": summarize(reasons)}
                        if state == "not_applicable_no_events":
                            # an inapplicable target's empty cell is complete history only if retrieval was
                            detail["retrieval_complete"] = not rule_partial and not result.partial
                        self.repo.save_baseline_window_cell(self.hunt_id, {
                            "rule_id": pb.id, "version": pb.spec.version, "target": target,
                            "partition": pkey, "state": state, "matched": 0,
                            "evaluated": evaluated, "detail": detail,
                        }, ())
                        continue
                    try:
                        stage = self._event_stage()
                        stage.record_baseline_cell(
                            target=target, partition=pkey, start=w.start, end=w.end,
                            target_applicable=target_applicable, source_complete=not rule_partial,
                            reasons=reasons, task_id=tid, events=carry_events,
                            observations=result.observations, pendings=result.pendings,
                            counts=result.counts, scope_hours=result.scope_hours,
                            event_hours=result.event_hours,
                        )
                        # Compact rows share the stage volume with citations and are billed with them.
                        self._charge_stage(stage)
                    except sqlite3.OperationalError as exc:
                        reason = f"compact baseline stage failed ({exc})"
                        self.budget.fail(reason)
                        self.partial_reasons.append(f"{target} {pkey}: {reason}")
                        self.repo.save_baseline_window_cell(self.hunt_id, {
                            "rule_id": pb.id, "version": pb.spec.version, "target": target,
                            "partition": pkey, "state": "evaluated_partial", "matched": 0,
                            "evaluated": evaluated, "detail": {"reasons": summarize([*reasons, reason])},
                        }, ())
                    continue
                pb.begin_cell(
                    pkey, (w.start, w.end), KeyContext(is_internal=netdef.current().is_internal),
                )
                before_eval = pb.evaluated
                pb.consume_scoped_partition(ordered)
                result = pb.finish_cell()
                reasons.extend(result.reasons)
                evaluated = pb.evaluated - before_eval
                if not target_applicable:
                    state = "not_applicable_no_events"
                elif rule_partial or result.partial:
                    state = "evaluated_partial"
                elif not (evaluated_families & families) and evaluated == 0:
                    state = "not_applicable_no_events"
                else:
                    state = "evaluated_complete"
                self._save_baseline_cell(
                    pb, target, pkey, state, evaluated, reasons, result, tid, ordered, raw_sources,
                    retrieval_complete=not rule_partial and not result.partial,
                )
                continue
            before_eval, before_missing, before_os, before_capped = (
                pb.evaluated, pb.missing_required, pb.os_applicable, pb.capped,
            )
            before_assumed = pb.direction_assumed
            before_limits = {name: limit.records for name, limit in pb.limits.items()}
            scoped_events = pb.scope_partition(events)
            # Every rule reads every batch, whatever the state budget: a store in no-growth mode refuses only
            # records that need a new key in it (each rule's own refusal path), and every match that needs no new
            # state still publishes.
            pb.bind_raw(raw_sources, target)
            try:
                matches = pb.consume_scoped_partition(scoped_events)
            except StateExhausted as exc:
                # a write to the stage volume failed mid-batch (a rule that writes rows directly): the records it
                # had not evaluated yet are refused, counted exactly
                matches = []
                pb.refuse_unevaluated(scoped_events,
                                      pb.evaluated - before_eval + pb.missing_required - before_missing
                                      + pb.capped - before_capped,
                                      f"a write to the stage volume failed ({exc}); this rule's later records of "
                                      f"the batch are not evaluated")
            pb.bind_raw({})
            self._record_playbook_batch(pb, matches, raw_sources, tid, staged, held, released)
            evaluated = pb.evaluated - before_eval
            missing = pb.missing_required - before_missing
            target_applicable = target_fallback or pb.os_applicable > before_os
            rule_partial = target_applicable and rule_partial
            # records a full state budget kept from evaluation: never a clean evaluation of this partition
            capped = pb.capped - before_capped
            # records skipped or judged for a direction the default internal-network definition only assumes
            assumed = pb.direction_assumed - before_assumed
            incomplete = rule_partial or bool(missing) or bool(capped) or bool(assumed)
            if not target_applicable:
                state = "not_applicable_no_events"
            elif not (evaluated_families & families) and evaluated == 0:
                state = "not_applicable_no_events" if not rule_partial else "evaluated_partial"
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
            reasons.extend(windows_reasons)
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
        if windows_gate_reasons:
            self.partial_reasons.append(
                f"{target} {pkey}: " + "; ".join(sorted(windows_gate_reasons))
            )
        if staged or held or released:
            self._stage_put(list(staged.values()), raw_sources, held, released)
        staged.clear()
        # the event stage shares the stage volume: its growth counts toward the free-space reserve
        self.budget.check_free()
        # the partition's cells together: a crash before this leaves them all visibly `planned`
        self.repo.set_rule_cells(self.hunt_id, cells)
        self.repo.update_task(tid, "evaluated")

    def _baseline_target_applicable(self, target: str, playbook: BaselinePlaybook) -> bool:
        """Whether the target can deliver the spec's families, by the rule the baseline stage's history uses."""
        if self._profiles is None:
            self._profiles = self.repo.source_profiles(self.hunt_id)
        return playbook.spec.id in baseline_applicability(
            self._profiles, self.contracts, [target], [playbook.spec],
        )[target]

    def _baseline_observations(self, playbook: BaselinePlaybook, cell: BaselineCell):
        for row in cell.observations:
            yield {
                "hunt_id": self.hunt_id,
                "spec_id": playbook.spec.id,
                "spec_version": playbook.spec.version,
                **row,
                "history_count": None,
                "history_decayed": None,
                "peer_scopes_with_key": None,
                "peer_scopes": None,
                "threshold": None,
                "mean": None,
                "sigma": None,
                "n_hours": None,
                "verdict": "unresolved",
                "reason": "baseline judgement pending",
                "candidate_id": None,
            }

    def _save_baseline_cell(self, playbook: BaselinePlaybook, target: str, partition: str,
                            state: str, evaluated: int, reasons: list[str], result: BaselineCell,
                            task_id: str | None, events: list[TypedEvent], raw_sources: dict[str, dict], *,
                            retrieval_complete: bool = True) -> None:
        """Persist observations and the cell's idempotency marker; citations are fetched only if published."""
        del task_id, events, raw_sources
        detail: dict = {"reasons": summarize(reasons)}
        if state == "not_applicable_no_events":
            # An inapplicable target's empty cell is complete history only if its retrieval was complete.
            detail["retrieval_complete"] = retrieval_complete
        if playbook.spec.measure == "rate" and result.partial:
            detail.update(
                partial_hours=[hour.isoformat() for hour in result.partial_hours],
                partial_unscoped_hours=[hour.isoformat() for hour in result.partial_unscoped_hours],
                partial_host_hours={
                    host: [hour.isoformat() for hour in hours]
                    for host, hours in result.partial_host_hours
                },
                whole_cell_partial=result.whole_cell_partial,
            )
        counts = result.counts
        tokens = sum(1 for row in counts if row.get("token"))
        if tokens:
            # Dedup tokens are kept only for hours a cell shares with other cells; they are charged to one budget
            # per hunt. Over it, the cell's token material is not kept and the cell is never written as history
            # (its detection counts are unaffected).
            if self._baseline_token_rows is None:
                self._baseline_token_rows = self.repo.baseline_window_token_rows(self.hunt_id)
            if self._baseline_token_rows + tokens > BASELINE_TOKEN_ROWS_PER_HUNT:
                counts = tuple(row for row in counts if not row.get("token"))
                detail["material_complete"] = False
                detail["reasons"] = sorted({*detail["reasons"], (
                    f"dedup token material over the hunt's budget of {BASELINE_TOKEN_ROWS_PER_HUNT} rows: "
                    "this cell's hours are not written as baseline history")})
            else:
                self._baseline_token_rows += tokens
        self.repo.save_baseline_window_cell(self.hunt_id, {
            "rule_id": playbook.id,
            "version": playbook.spec.version,
            "target": target,
            "partition": partition,
            "state": state,
            "matched": 0,
            "evaluated": evaluated,
            "detail": detail,
        }, self._baseline_observations(playbook, result),
            counts=counts, scope_hours=result.scope_hours, event_hours=result.event_hours)

    def _finalize_baseline_target(self, target: str) -> None:
        """Persist compact exec-pair cells for post-lookback resolution and resume."""
        playbook = next((pb for pb in self.pack
                         if isinstance(pb, BaselinePlaybook) and pb.id == "bl.exec_pair"), None)
        stage = getattr(self, "_stage", None)
        if playbook is None or stage is None:
            return
        items = sorted(stage.baseline_cells(target), key=lambda item: (item["start"], item["partition"]))
        for item in items:
            if self.repo.baseline_window_cell_done(
                    self.hunt_id, playbook.id, playbook.spec.version, target, item["partition"]):
                stage.drop_baseline_cell(target, item["partition"])
                continue
            self.repo.stage_baseline_window_cell(
                self.hunt_id, {
                    **item, "target": target, "spec_version": playbook.spec.version,
                    "evaluated": sum(row.get("family", "process_exec") == "process_exec"
                                     for row in stage.baseline_execs(target, item["partition"])),
                },
                stage.baseline_execs(target, item["partition"]),
                stage.baseline_observations(target, item["partition"]),
                [asdict(pending) for pending in stage.baseline_pendings(target, item["partition"])],
                stage.baseline_counts(target, item["partition"]),
                stage.baseline_scope_hours(target, item["partition"]),
                stage.baseline_event_hours(target, item["partition"]),
            )
            stage.drop_baseline_cell(target, item["partition"])

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
            stage = self._stage = EventStage(
                self.stage_dir,
                budget=getattr(self, "budget", None),
                windows_account=getattr(self, "_windows_seen_account", None),
            )
        return stage

    def _windows_continuity(self) -> RecordIdContinuity:
        continuity = self._windows_record_ids
        if continuity is None:
            continuity = self._windows_record_ids = RecordIdContinuity(
                self._event_stage().directory,
                budget=self.budget,
                account=self._windows_continuity_account,
            )
        return continuity

    def _windows_script_blocks(self) -> ScriptBlockAssembler:
        assembler = self._windows_scripts
        if assembler is None:
            assembler = self._windows_scripts = ScriptBlockAssembler(
                self._event_stage().directory,
                budget=self.budget,
                account=self._windows_scripts_account,
            )
        return assembler

    def _finalize_windows_script_blocks(self) -> None:
        assembler = getattr(self, "_windows_scripts", None)
        if assembler is None:
            return
        finalized = 0
        matched: Counter[str] = Counter()
        evaluated: Counter[str] = Counter()
        for batch in batched(assembler.finalize(), SCRIPT_FINALIZE_BATCH_SIZE):
            events = list(batch)
            finalized += len(events)
            raw_sources = assembler.sources_for(events)
            self.repo.save_evidence(self.hunt_id, events, raw_sources, None)
            staged: dict[str, TypedEvent] = {}
            held: list[tuple[str, TypedEvent]] = []
            released: list[tuple[str, list[str]]] = []
            for pb in self.pack:
                if isinstance(pb, BaselinePlaybook) or "script_block" not in pb.families:
                    continue
                scoped = pb.scope_partition(events)
                if not scoped:
                    continue
                evaluated[pb.id] += len(scoped)
                pb.bind_raw(raw_sources, "script-block-finalize")
                try:
                    matches = pb.consume_scoped_partition(scoped)
                except StateExhausted as exc:
                    pb.note_limit("script_reassembly", f"incomplete script blocks were not evaluated ({exc})")
                    matches = []
                finally:
                    pb.bind_raw({})
                matched[pb.id] += len(matches)
                self._record_playbook_batch(pb, matches, raw_sources, None, staged, held, released)
            if staged or held or released:
                self._stage_put(list(staged.values()), raw_sources, held, released)
            self.budget.check_free()
        if not finalized:
            return
        reason = f"PowerShell script-block reassembly incomplete for {finalized} block(s); missing parts stated"
        self.partial_reasons.append(reason)
        for pb in self.pack:
            if not evaluated[pb.id]:
                continue
            self.repo.set_rule_cell(
                self.hunt_id, pb.id, pb.version, "script-block-finalize", "incomplete",
                "match_on_partial" if matched[pb.id] else "evaluated_partial",
                matched[pb.id], evaluated[pb.id], {"reasons": [reason]},
            )

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
        self.budget.finalizing = True           # finalize re-reads kept state: only the free-space reserve applies
        self._finalize_windows_script_blocks()
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
                raw_sources = ({**agg_raw, **self._merge_staged_match_raw(m)} if pb.staged else agg_raw)
                self._publish(m, None, raw_sources)
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
            reasons += limits + pb.coverage_notes()
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
        """Remove the disk stage, Windows continuity state and playbook spills on every controlled exit path."""
        continuity = getattr(self, "_windows_record_ids", None)
        if continuity is not None:
            continuity.close()
            self._windows_record_ids = None
        scripts = getattr(self, "_windows_scripts", None)
        if scripts is not None:
            scripts.close()
            self._windows_scripts = None
        stage = getattr(self, "_stage", None)
        if stage is not None:
            stage.close()
            self._stage = None
        for pb in getattr(self, "pack", ()):
            pb.close_spill()
