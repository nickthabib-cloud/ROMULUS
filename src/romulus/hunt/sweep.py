"""The deterministic sweep: plan partitions, stream every partition through normalization and all
playbooks, publish direct findings immediately, and keep an exact per-rule coverage ledger."""
from __future__ import annotations

import logging
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from itertools import batched

import httpx
from sqlalchemy.exc import SQLAlchemyError

from romulus.baseline.carry import HourParents
from romulus.baseline.playbook import BaselineCell, BaselinePlaybook
from romulus.baseline.reasons import summarize
from romulus.baseline.spec import KeyContext, exec_serial
from romulus.content.sigma_coverage import (
    bounded_details,
    coverage_view,
    exclusion_reasons,
    reason_signature,
    visible_reasons,
)
from romulus.detect import netdef
from romulus.detect.base import Match, Playbook
from romulus.detect.bounded import StateBudget, StateExhausted, live_stores
from romulus.detect.host import bind_lineage_citation_loader
from romulus.detect.netdef import DIRECTION_ASSUMED_REASON
from romulus.detect.observed import observation
from romulus.detect.registry import bind_windows_site, fresh_pack
from romulus.errors import SourceError
from romulus.evidence.linux_catalog import (
    LINUX_LOGICAL_DATASETS,
    LINUX_SHIPPER_DATASETS,
    LOGICAL_FAMILIES,
    dataset_selection,
    logical_of,
    shipper_names,
    text_dataset_inventory,
)
from romulus.evidence.normalize import (
    BOOT_FILL_FAMILIES,
    BOOT_INTERVAL_ORIGIN,
    RPC_REMOTE_SCOPE_SKIP,
    BootIntervals,
    normalize_hits,
)
from romulus.evidence.typed import TypedEvent
from romulus.evidence.windows import (
    NXLOG_CHANNEL_SKIP,
    RecordIdContinuity,
    windows_record_signature,
    windows_view,
)
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
from romulus.evidence.zeek import ZEEK_INTERIM_SUPERSEDED, ZEEK_NORMALIZER
from romulus.evidence.zeek_catalog import MALCOLM, SHAPES, ZEEK_LOGS, lookup_log
from romulus.hunt.publish import (
    LineageCitationFetcher,
    SourceCitationFetcher,
    WindowsCitationFetcher,
    bind_aggregate_history,
    publish_match,
)
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
# The logical Linux datasets (linux_catalog.LINUX_SHIPPER_DATASETS names the shipper datasets each one reads).
LINUX_HOST_DATASETS = LINUX_LOGICAL_DATASETS
HOST_DATASETS = [*LINUX_HOST_DATASETS, *WINDOWS_HOST_DATASETS]
NET_FAMILIES ={"net_alert", "net_flow", "dns_query", "http_tx", "file_transfer", "tls_session", "ssh_session"}
# linux.audit now also yields `auth` (USER_LOGIN/USER_START), so an unparseable audit group may hide one.
# A login group that fails is tagged linux.audit.auth; it takes every record of its event, so it may also hide
# an exec, socket or file record of that event and carries the whole audit family set.
_AUDIT_ADMIN = {"account_change", "service_change", "audit_config", "system_state"}
LINUX_DATASET_FAMILIES = {
    **{logical: set(families) for logical, families in LOGICAL_FAMILIES.items()},
    "linux.audit.socket": {"net_socket", "process_observed"},
    "linux.audit.file": {"file_change", "file_access", "process_observed"},
    "linux.audit.module": {"kernel_module", "process_observed"},
    "linux.audit.observed": {"process_observed"},
    "linux.audit.auth": {"process_exec", "net_socket", "auth", "file_change", "file_access", "kernel_module", "process_observed"} | _AUDIT_ADMIN,
    "linux.audit.admin": _AUDIT_ADMIN,
    # a shipper's dataset name feeds the families of its logical dataset (a profile's inventory lists these names)
    **{name: set(LOGICAL_FAMILIES[logical_of(name)]) for name in shipper_names()
       if name not in LOGICAL_FAMILIES},
    "arkime.session": {"net_session"},
    **{f"suricata.eve.{event_type}": NET_FAMILIES for event_type in (
        "alert", "flow", "netflow", "dns", "http", "fileinfo", "tls", "ssh",
    )},
    # Filebeat's suricata module and the Agent's Suricata integration name every EVE event type "suricata.eve"
    "suricata.eve": NET_FAMILIES,
}
# Every catalogued Zeek log by its dispatch token (`zeek:conn`, never the bare name, which other shippers' datasets
# share): the family its records feed. A normalization error on a Zeek record is tagged with its token.
ZEEK_DATASET_FAMILIES = {log.token: frozenset({log.family}) for log in ZEEK_LOGS}
DATASET_FAMILIES = {**LINUX_DATASET_FAMILIES, **WINDOWS_DATASET_FAMILIES, **ZEEK_DATASET_FAMILIES}
ALL_FAMILIES = frozenset({"*"})
# Zeek's provider in a Malcolm index; the other providers there (Suricata, Arkime) are read by their own normalizers.
ZEEK_PROVIDER = "zeek"
# How many Zeek connections (sensor and uid) whose interim record a partition evaluated are kept on disk to tell a
# later record of the same connection from another target. Beyond it a connection's later record is still evaluated,
# and the reason says counts over such connections may include both records.
ZEEK_INTERIM_KEYS_LIMIT = 5_000_000
# Failures of what every rule depends on (the store, the stage volume, the source): they end the sweep and fail the
# hunt. Any other exception a rule raises is that rule's own defect: its cells are failed, named, and the others go on.
INFRASTRUCTURE_ERRORS = (sqlite3.Error, SQLAlchemyError, OSError, MemoryError, SourceError, httpx.HTTPError)
RULE_FAILURE_TEXT = 300
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
NXLOG_MIXED_GATE = ("Windows collection not attested: NXLog flat records on a Linux target; continuity and "
                    "event-class inventory not assessed")


def _error_tag(message: str) -> str:
    """The dataset a normalization error names ("linux.audit: ...", "zeek:conn: ..."): a Zeek dispatch token keeps its
    own colon."""
    if message.startswith("zeek:") and message[len("zeek:"):][:1] not in ("", " "):
        return "zeek:" + message[len("zeek:"):].split(":", 1)[0].strip()
    return message.split(":", 1)[0].strip()


def zeek_log_of_dataset(dataset: str):
    """The catalogued Zeek log a shipper's `zeek.<name>` dataset or a `zeek:<log>` dispatch token names, in any
    shape's naming; None for anything else (including Zeek logs outside the catalog)."""
    if dataset.startswith("zeek:"):
        name = dataset[len("zeek:"):]
        return next((log for log in ZEEK_LOGS if log.name == name), None)
    if dataset.startswith("zeek."):
        name = dataset[len("zeek."):]
        return next((log for shape in SHAPES if (log := lookup_log(shape, name)) is not None), None)
    return None


def _dataset_families(dataset: str) -> frozenset[str]:
    families = DATASET_FAMILIES.get(dataset)
    if families is not None:
        return families
    log = zeek_log_of_dataset(dataset)
    return frozenset({log.family}) if log is not None else frozenset()


def _families_of(datasets) -> frozenset[str]:
    return frozenset().union(*(_dataset_families(dataset) for dataset in datasets))


_WINDOWS_FAMILIES = frozenset().union(*WINDOWS_DATASET_FAMILIES.values())
_ZEEK_FAMILIES = frozenset().union(*ZEEK_DATASET_FAMILIES.values())
_ROLE_FAMILIES = {
    "host": _families_of(HOST_DATASETS),
    "network": _families_of([*(name for name in DATASET_FAMILIES if name.startswith("suricata.eve.")),
                             "arkime.session"]) | _ZEEK_FAMILIES,
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
        self._windows_dynamic_classes: dict[str, tuple] = {}
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
        self.pack: list[Playbook] = bind_windows_site(fresh_pack(), self.site_facts)
        manifest = repo.get_hunt(hunt_id)['manifest'] if repo is not None else {}
        indicator_pins = manifest.get('indicator_lists')
        if manifest.get('sigma_rules'):
            from romulus.content.sigma_store import load_pinned
            from romulus.detect.sigma import SigmaRule
            self.pack.extend(SigmaRule(row) for row in load_pinned(repo, manifest['sigma_rules']))
        for pb in self.pack:
            if hasattr(pb, 'bind_indicators'):
                pb.bind_indicators(repo, indicator_pins)
        bind_lineage_citation_loader(self.pack, LineageCitationFetcher(client, contracts).load)
        for pb in self.pack:
            bind_aggregate_history(repo, hunt_id, pb)
            pb.spill_dir = stage_dir          # a playbook's on-disk join tables live beside the event stage
            pb.budget = self.budget
            pb.window_start = window.start
            pb.window_end = window.end
            if pb.id == "host.telemetry_gap_after_tamper":
                pb.persisted_loader = lambda ids: [
                    TypedEvent.model_validate(row["event"]) for row in repo.citation_events(hunt_id, ids)]
            if hasattr(pb, "citation_fields"):
                pb.citation_fetcher = WindowsCitationFetcher(client)
            else:
                pb.citation_fetcher = SourceCitationFetcher(client)
        self._has_windows = any(contract is not None and contract.os_family == "windows"
                                for contract in contracts.values())
        # Plan only detection stores. Citation owners have no floor and yield their optional cache bytes first.
        # Windows hunts additionally own id-only delivery, continuity and script assembly state.
        stage_owners = [pb for pb in self.pack if pb.staged and not hasattr(pb, "citation_fields")]
        self.budget.plan(live_stores(self.pack) + 1 + (3 if self._has_windows else 0))
        self._stage_account = self.budget.account("event_stage")
        self._stage_owner_accounts = {pb.id: self.budget.account("event_stage:"+pb.id,
                                                               strong=pb.state_slice == "strong", yields=True)
                                      for pb in stage_owners}
        self._stage_owners = {}
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
        # rule id -> why the rule failed: it is not evaluated again in this hunt, and every later cell says so
        self.failed_rules: dict[str, str] = {}
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
        stage.owners = self._stage_owners
        self._stage_owners = {}
        # A bound can be replaced many times within one partition. Its new hold and release cancel
        # before disk admission; only the surviving references need storage or source-body pages.
        released_counts = Counter((owner, identity) for owner, ids in released for identity in ids)
        surviving = []
        for owner, event in held:
            key = (owner, event.id)
            if released_counts[key]:
                released_counts[key] -= 1
            else:
                surviving.append((owner, event))
        released_by_owner = defaultdict(list)
        for (owner, identity), count in released_counts.items():
            released_by_owner[owner].extend([identity]*count)
        try:
            if events:
                stage.put(events, raw_sources)
            stage.hold(surviving, raw_sources)
            for owner, ids in released_by_owner.items():
                stage.release(owner, ids)
        except sqlite3.OperationalError as exc:
            self.budget.fail(f"writing the event stage failed ({exc})")
            for pb in self.pack:
                if pb.staged:
                    pb.note_limit("stage", f"the event stage could not take this partition's citations "
                                           f"({self.budget.broken}); findings that cite them are not computed")
            return
        except (ValueError, UnicodeError) as exc:
            # a citation the stage cannot serialize (the stage replaces lone surrogates, so this is a last resort):
            # the rules that cite this partition's records say so, and the sweep goes on
            log.warning("event stage could not serialize a partition's citations: %s", exc.__class__.__name__)
            for pb in self.pack:
                if pb.staged:
                    pb.note_limit("stage", f"the event stage could not serialize this partition's citations "
                                           f"({exc.__class__.__name__}); findings that cite them are not computed")
            return
        self._charge_stage(stage)
        stage.owners = {}

    def _record_playbook_batch(
        self,
        pb: Playbook,
        matches: Iterable[Match],
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
            # Full-body joining rules share the stage's bounded byte allowance, including strong rules.
            # Reference-only authentication bursts return no full bodies here.
            drained = pb.drain_staged()
            held_ids, released_ids = pb.drain_bounds()
            if released_ids:
                released.append((pb.id, released_ids))
            account = self._stage_owner_accounts.get(pb.id, self._stage_account)
            # An event returned more often than it is held is also staged to be kept.
            holds = Counter(held_ids)
            copies = Counter(event.id for event in drained)
            for event in drained:
                if copies[event.id] > holds[event.id]:
                    staged.setdefault(event.id, event)
                    self._stage_owners.setdefault(event.id, []).append(account)
            for event in {event.id: event for event in drained if holds[event.id]}.values():
                held.extend([(pb.id, event)] * holds[event.id])
        elif pb.kind == "aggregate":
            # Aggregates retain examples: stash raw copies of their retained events now.
            self._retain_aggregate_raw(pb, raw_sources)

    def _charge_stage(self, stage: EventStage) -> None:
        """Charge the stage file's growth beyond the most it has held to the event stage's account."""
        stage.charge_growth()

    def _publish(self, m: Match, task_id: str | None, raw_sources: dict[str, dict]):
        playbook = next(playbook for playbook in self.pack if playbook.id == m.playbook_id)
        if m.raw_copies:
            raw_sources = {**m.raw_copies, **raw_sources}      # records the rule kept for citation itself
        if any(event.get("observer.product") == "zeek" for event in m.events):
            from romulus.hunt.zeek_gaps import enrich
            enrich(self, m, raw_sources)
        row = publish_match(self.repo, self.hunt_id, playbook, m, task_id, raw_sources)
        if m.playbook_id in {"host.download_then_execute", "host.authorized_key_then_login"}:
            for observer in self.pack:
                if observer.id == "host.tool_cleanup":
                    observer.observe_linked_match(m)
        if m.playbook_id in {"host.audit_rules_tamper", "host.security_or_logging_service_stop",
                             "host.log_or_history_clearing"}:
            for observer in self.pack:
                if observer.id == "host.telemetry_gap_after_tamper":
                    observer.observe_tamper_match(m)
        if row is not None:
            self.stats["candidates"] += 1
            self.on_candidate(row)

    def _filters_for(self, target: str, contract: FieldContract | None = None) -> list[Predicate]:
        if contract is not None and contract.role == "host":
            if contract.os_family == "windows":
                return []
            datasets = LINUX_HOST_DATASETS
            plain, with_module, undated, unsearchable = dataset_selection(
                datasets, module_searchable=contract.supports("event.module", "eq"),
                input_type_searchable=contract.supports("input.type", "eq"))
            # recorded so the report can list the target's other datasets as not assessed: every shipper dataset
            # name the query selects on this target (it expands each logical dataset to its shapes when compiled)
            self.stats.setdefault("dataset_filter", {})[target] = [
                *plain, *(name for name, _module in with_module if name not in plain)]
            self._note_linux_shapes(target, datasets, unsearchable, contract, undated)
            if contract.nxlog_mixed:
                # selected with NXLog's flat Windows records instead (`_any_of_for`): either shape, each as alone
                return []
            return [Predicate(field="event.dataset", op="in", value=list(datasets))]
        return []

    def _note_linux_shapes(self, target: str, datasets, unsearchable: list[str], contract: FieldContract | None = None,
                           undated=()) -> None:
        """Record, once per target, which shipper shapes of the Linux datasets the target's inventory holds (with
        their counts) and which shapes it cannot search (a field the shape needs is not searchable): those are not
        assessed, never read as having no records. Documents that name no dataset (journald, Auditbeat) are not in
        the dataset inventory: each such searchable shape is counted over the hunt window."""
        if target in self.stats.get("linux_shipper_inventory", {}):
            return
        if getattr(self, "_profiles", None) is None and hasattr(getattr(self, "repo", None), "source_profiles"):
            self._profiles = self.repo.source_profiles(self.hunt_id)
        profile = (getattr(self, "_profiles", None) or {}).get(target) or {}
        inventory = profile.get("datasets") or {}
        present: dict[str, dict[str, int]] = {}
        if "linux.text" in datasets:
            if contract is None or any(contract.supports(name, "exists") for name in ("message", "event.original")):
                text_inventory = text_dataset_inventory(inventory)
                present["linux.text"] = text_inventory
                selected = self.stats.get("dataset_filter", {}).get(target)
                samples = (profile.get("linux_text") or {}).get("samples") or {}
                for name in text_inventory:
                    sample = samples.get(name) or {}
                    has_payload = any(count > 0 for form, count in (sample.get("formats") or {}).items()
                                      if form != "no_text_payload")
                    if has_payload:
                        if selected is not None and name not in selected:
                            selected.append(name)
                    else:
                        decided = sample.get("sampled", 0) > 0 and sample.get(
                            "sample_complete", sample.get("complete", False))
                        reason = "no text payload in sample" if decided else "sample incomplete"
                        self.stats.setdefault("linux_text_not_retrieved", {}).setdefault(target, {})[name] = reason
            else:
                unsearchable = [*unsearchable, "linux.text"]
        for logical in datasets:
            for shape in LINUX_SHIPPER_DATASETS.get(logical, ()):
                if shape.dataset is not None and shape.dataset in inventory:
                    present.setdefault(logical, {})[shape.dataset] = inventory[shape.dataset]
        for logical in datasets:
            for shape in LINUX_SHIPPER_DATASETS.get(logical, ()):
                if shape.undated is not None and shape.undated in undated:
                    count = self._undated_shape_count(target, contract, shape.undated)
                    present.setdefault(logical, {})[shape.key] = count if count is not None else "not counted"
        self.stats.setdefault("linux_shipper_inventory", {})[target] = present
        if unsearchable:
            self.stats.setdefault("linux_shapes_not_assessed", {})[target] = [
                f"{key}: not searchable on this target (the field this shape is selected by is not mapped)"
                for key in unsearchable]

    def _undated_shape_count(self, target: str, contract: FieldContract | None, selector: tuple[str, str]) -> int | None:
        """How many window documents name no dataset and carry `selector` (field, value); None when it cannot be
        counted exactly (the field is not aggregatable, or the source did not answer in full)."""
        field, value = selector
        spec = contract.spec(field) if contract is not None else None
        if (spec is None or not spec.aggregatable or not contract.supports("event.dataset", "missing")
                or getattr(self, "client", None) is None):
            return None
        try:
            outcome = execute(self.client, SearchIntent(
                kind="aggregate", target=target, window=self.window,
                filters=[Predicate(field="event.dataset", op="missing"), Predicate(field=field, op="eq", value=value)],
                group_by=[field], purpose="linux dataset-less shape inventory"), contract)
        except Exception:  # noqa: BLE001 - an inventory count never fails the sweep; it is reported as not counted
            return None
        if outcome.completeness != Completeness.complete:
            return None
        return sum(int(bucket.get("count") or 0) for bucket in outcome.buckets)

    def _any_of_for(self, target: str, contract: FieldContract | None = None) -> list[list[Predicate]]:
        """Select only normalized source shapes while preserving each target's other known datasets."""
        if contract is not None and contract.role == "network":
            return self._zeek_catalog_filter(target, contract)
        if contract is not None and contract.role == "host" and contract.os_family != "windows" and contract.nxlog_mixed:
            # a Linux target that also holds NXLog's flat Windows records: the Linux datasets or the flat shape
            flat = self._nxlog_selector(target, contract)
            linux = [Predicate(field="event.dataset", op="in", value=list(LINUX_HOST_DATASETS))]
            if flat is None:
                return [linux]
            self.stats.setdefault("windows_shape_notes", {})[target] = [(
                "windows.nxlog: on this Linux target NXLog's flat Windows records are selected by shape; Windows "
                "record continuity, the event-class inventory and value queries on them are not assessed")]
            return [linux, flat]
        # Winlogbeat may omit event.dataset, so Windows also selects by native channel.
        if contract is None or contract.role != "host" or contract.os_family != "windows":
            return []
        read_tokens = getattr(self, "_windows_read_tokens", {}).get(target)
        wfp_reader = any("network_filter" in (*rule.families, *rule.context_families) for rule in getattr(self, "pack", ()))
        rdp_reader = any("remote_access" in (*rule.families, *rule.context_families) for rule in getattr(self, "pack", ()))
        rpc_reader = any("rpc_call" in (*rule.families, *rule.context_families) for rule in getattr(self, "pack", ()))
        sigma_classes = {(str(c).casefold(), str(p).casefold(), int(i))
                         for rule in getattr(self, 'pack', ()) if getattr(rule, 'id', '').startswith('sigma.')
                         for c, p, i in rule.windows_event_classes}
        rpc_groups = []
        strict_rpc = False
        if rpc_reader:
            from romulus.hunt.windows_filters import rpc_call_groups

            rpc_groups, strict_rpc = rpc_call_groups(contract)
            if not strict_rpc:
                reason = ("RPC exact transport/interface filtering unavailable; available provider/code predicates "
                          "are used, or unrestricted retrieval when neither is expressible; local or untyped "
                          "transports and unclassified interfaces are withheld by typed fields before staging.")
                reasons = self._windows_inventory_reasons.setdefault(target, [])
                if reason not in reasons:
                    reasons.append(reason)
            if any(not group for group in rpc_groups):
                return []
        class_searchable = all(contract.supports(field, "eq") for field in (
            "event.channel", "event.provider", "event.code"))
        if (rdp_reader or wfp_reader) and not class_searchable:
            reason = ("Windows event-class mapping cannot restrict WFP 5156/5158 or RdpCoreTS 131/132/148; "
                      "base dataset/channel fallback accepts their volume; no Windows classes withheld.")
            reasons = self._windows_inventory_reasons.setdefault(target, [])
            if reason not in reasons:
                reasons.append(reason)
        if rdp_reader and read_tokens is None and class_searchable:
            families = {family for rule in getattr(self, "pack", ()) for family in (*rule.families, *rule.context_families)}
            read_tokens = {event.token for event in EVENT_CLASSES if event.family in families}
            reason = "Windows class inventory unavailable; RdpCoreTS retrieval uses explicitly declared classes"
            reasons = self._windows_inventory_reasons.setdefault(target, [])
            if reason not in reasons:
                reasons.append(reason)
        if wfp_reader and read_tokens is None and class_searchable:
            families = {family for rule in getattr(self, "pack", ()) for family in (*rule.families, *rule.context_families)}
            read_tokens = {event.token for event in EVENT_CLASSES if event.family in families}
            reason = "Windows class inventory unavailable; retrieval uses known class scopes, with dynamic providers unresolved"
            reasons = self._windows_inventory_reasons.setdefault(target, [])
            if reason not in reasons:
                reasons.append(reason)
        if read_tokens is not None and all(contract.supports(field, "eq") for field in (
                "event.channel", "event.provider", "event.code")):
            control_tokens = {
                event.token for event in EVENT_CLASSES
                if event.key in COLLECTION_CHANGE_EVENTS
            }
            selected = [event for event in EVENT_CLASSES if event.token in read_tokens | control_tokens]
            selected.extend(event for event in self._windows_dynamic_classes.get(target, ())
                            if event.token in read_tokens)
            from romulus.hunt.windows_filters import is_rdp_core, rdp_channel_groups, rdp_class_requested

            selected = [event for event in selected if not is_rdp_core(event) or rdp_class_requested(event, getattr(self, "pack", ()))]
            if selected:
                self._windows_selective.add(target)
                self.stats.setdefault("windows_class_filter", {})[target] = [event.token for event in selected]
                object_readers = {playbook.id for playbook in getattr(self, "pack", ())
                                  if "windows" in playbook.os_families
                                  and "object_access" in (*playbook.families, *playbook.context_families)}
                process_only = object_readers == {"win.lsass_process_access"} and contract.supports("object.type", "eq")
                groups = list(rpc_groups)
                for event in selected:
                    if event.key in sigma_classes:
                        groups.append([Predicate(field='event.channel', op='eq', value=event.channel),
                                       Predicate(field='event.provider', op='eq', value=event.provider),
                                       Predicate(field='event.code', op='eq', value=event.event_id)])
                        continue
                    if event.family == "rpc_call":
                        continue
                    group = [Predicate(field="event.channel", op="eq", value=event.channel),
                             Predicate(field="event.provider", op="eq", value=event.provider),
                             Predicate(field="event.code", op="eq", value=event.event_id)]
                    if is_rdp_core(event):
                        scoped_groups = rdp_channel_groups(contract, group, event, getattr(self, "pack", ()))
                        if scoped_groups is None:
                            reason = "RdpCoreTS channel records not fetched: mapping cannot filter native ChannelName"
                            reasons = self._windows_inventory_reasons.setdefault(target, [])
                            if reason not in reasons:
                                reasons.append(reason)
                        else:
                            groups.extend(scoped_groups)
                        continue
                    if event.family == "network_filter":
                        # WFP auditing can dwarf all other host telemetry. Only the
                        # declared loopback-tunnel predicate reads these connections.
                        if event.event_id != 5156:
                            continue
                        from romulus.hunt.windows_filters import wfp_tunnel_groups

                        scoped_groups = wfp_tunnel_groups(contract, group)
                        if scoped_groups is None:
                            reason = "WFP tunnel records not fetched: mapping cannot filter native ports and loopback addresses"
                            reasons = self._windows_inventory_reasons.setdefault(target, [])
                            if reason not in reasons:
                                reasons.append(reason)
                        else:
                            groups.extend(scoped_groups)
                        continue
                    if process_only and event.family == "object_access":
                        group.append(Predicate(field="object.type", op="eq", value="Process"))
                    groups.append(group)
                self.stats.setdefault("windows_process_object_filter", {})[target] = process_only
                if not groups:
                    # Empty any_of means no restriction to the compiler. If every
                    # requested class was deliberately withheld, issue an explicit
                    # contradiction instead of accidentally fetching all telemetry.
                    return [[Predicate(field="event.code", op="exists"),
                             Predicate(field="event.code", op="missing")]]
                flat = self._nxlog_selector(target, contract)
                if flat is not None and not self._nxlog_aliased(contract):
                    # the class predicates read Winlogbeat's names only here: NXLog's flat records by their shape
                    groups.append(flat)
                return groups
        if rpc_groups and not any(contract.supports(field, "in") for field in ("event.dataset", "event.channel")):
            # The ordinary Windows fallback was unrestricted; RPC must not narrow it.
            return []
        groups: list[list[Predicate]] = list(rpc_groups)
        if contract.supports("event.dataset", "in") and not (rpc_reader and strict_rpc
                and contract.supports("event.channel", "in")):
            groups.append([Predicate(field="event.dataset", op="in", value=list(WINDOWS_HOST_DATASETS))])
        if contract.supports("event.channel", "in"):
            groups.append([Predicate(field="event.channel", op="in", value=[channel for channel in WINDOWS_CHANNELS if channel])])
        flat = self._nxlog_selector(target, contract)
        if groups and flat is not None:
            # NXLog's flat records name no dataset and may spell a channel in any case: selected by their shape
            groups.append(flat)
        self.stats.setdefault("dataset_filter", {})[target] = list(WINDOWS_HOST_DATASETS)
        self.stats.setdefault("channel_filter", {})[target] = list(WINDOWS_CHANNELS)
        return groups

    def _nxlog_selector(self, target: str, contract: FieldContract) -> list[Predicate] | None:
        """The selector of NXLog's flat Windows records on a Windows target, or None; a target that cannot search
        their Channel and EventID is listed, once, as not assessing that shape (never as holding none of it)."""
        from romulus.hunt.windows_filters import nxlog_windows_group

        group = nxlog_windows_group(contract)
        if group is None:
            self.stats.setdefault("windows_shapes_not_assessed", {})[target] = [
                "windows.nxlog: not searchable on this target (Channel and EventID are not both mapped)"]
        elif contract.os_family == "windows" and not self._nxlog_aliased(contract):
            # the Windows aliases do not read the flat names (text-mapped, or a Winlogbeat alias they would narrow)
            self.stats.setdefault("windows_shape_notes", {})[target] = [(
                "windows.nxlog: Channel, SourceName, EventID or Hostname is not exact-searchable through the Windows "
                "fields on this target, so its records are selected by shape and value queries on them (event "
                "classes) are unresolved")]
        return group

    @staticmethod
    def _nxlog_aliased(contract: FieldContract) -> bool:
        """Whether the Windows class and host fields read NXLog's flat names exactly on this target."""
        return all(flat in ((spec := contract.fields.get(typed)) and spec.natives or ()) and contract.supports(typed, "eq")
                   for typed, flat in (("event.channel", "Channel"), ("event.provider", "SourceName"),
                                       ("event.code", "EventID"), ("host.name", "Hostname")))

    def _zeek_catalog_filter(self, target: str, contract: FieldContract) -> list[list[Predicate]]:
        """Leave out only the Zeek logs outside the catalog, which no normalizer reads and which feed no family a rule
        reads: they are listed as not retrieved (by the report, from the inventory), never as searched. Without a
        complete inventory naming such a log, or a contract that can select the rest exactly, everything is retrieved
        and those records are counted as not assessed when they are read."""
        if self._profiles is None:
            self._profiles = self.repo.source_profiles(self.hunt_id)
        profile = self._profiles.get(target) or {}
        if any(str(note).startswith("ds inventory truncated") for note in profile.get("notes") or []):
            return []
        datasets = sorted(profile.get("datasets") or {})
        inventory = profile.get("inventory")
        if isinstance(inventory, list) and inventory:
            # A mixed index (Malcolm: Zeek, Suricata and Arkime rows): Zeek's bare log names are told apart by provider.
            unread = sorted({str(item.get("dataset")) for item in inventory
                             if item.get("provider") == ZEEK_PROVIDER and isinstance(item.get("dataset"), str)
                             and lookup_log(MALCOLM, item["dataset"]) is None})
            if not unread or not all(contract.supports(field, op) for field, op in (
                    ("event.provider", "eq"), ("event.provider", "in"), ("event.provider", "missing"),
                    ("event.dataset", "in"), ("event.dataset", "missing"))):
                return []
            read = sorted({str(item["dataset"]) for item in inventory
                           if item.get("provider") == ZEEK_PROVIDER and isinstance(item.get("dataset"), str)
                           and lookup_log(MALCOLM, item["dataset"]) is not None})
            others = sorted({str(item["provider"]) for item in inventory
                             if isinstance(item.get("provider"), str) and item["provider"] != ZEEK_PROVIDER})
            groups: list[list[Predicate]] = []
            if read:
                groups.append([Predicate(field="event.provider", op="eq", value=ZEEK_PROVIDER),
                               Predicate(field="event.dataset", op="in", value=read)])
            # a Zeek row that names no log is read, and normalization decides what it is
            groups.append([Predicate(field="event.provider", op="eq", value=ZEEK_PROVIDER),
                           Predicate(field="event.dataset", op="missing")])
            if others:
                groups.append([Predicate(field="event.provider", op="in", value=others)])
            groups.append([Predicate(field="event.provider", op="missing")])
            unread_keys = {f"zeek:{name.strip().lower()}" for name in unread}
            self.stats.setdefault("dataset_filter", {})[target] = [key for key in datasets if key not in unread_keys]
            return groups
        unread = [dataset for dataset in datasets
                  if dataset.startswith("zeek.") and zeek_log_of_dataset(dataset) is None]
        if not unread or not (contract.supports("event.dataset", "in") and contract.supports("event.dataset", "missing")):
            return []
        read = [dataset for dataset in datasets if dataset not in unread]
        groups = [[Predicate(field="event.dataset", op="in", value=read)]] if read else []
        # A record without a dataset cannot be placed by the source query: it is read, and normalization decides.
        groups.append([Predicate(field="event.dataset", op="missing")])
        self.stats.setdefault("dataset_filter", {})[target] = read
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
            if (row := lookup_event_class(raw_channel, raw_provider, raw_event_id)) is not None and row.family == "rpc_call":
                malformed_identity = False
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
        # Named SQL instances are concrete classes resolved from the existing
        # bounded aggregate (at most SearchIntent.max_records buckets). Keep
        # those identities rather than searching for a literal wildcard provider.
        static_tokens = {event.token for event in EVENT_CLASSES}
        self._windows_dynamic_classes[target] = tuple(
            event for token, event in sorted(classes_by_token.items())
            if event.family == "database_audit" and token not in static_tokens
        )
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
            read_tokens.update(
                event_class.token for event_class in event_classes_for_families(
                    set(playbook.families) | set(playbook.context_families)
                )
            )
            if "database_audit" in (*playbook.families, *playbook.context_families):
                read_tokens.update(event.token for event in self._windows_dynamic_classes[target])
        from romulus.hunt.windows_filters import is_rdp_core, rdp_class_requested

        read_tokens.difference_update(event.token for event in EVENT_CLASSES
                                      if is_rdp_core(event) and not rdp_class_requested(event, self.pack))
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
            winlog = windows_view(record.get("_source") or {}).get("winlog") or {}
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
                source = windows_view(record.get("_source") or {})
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
            source = windows_view(record.get("_source") or {})
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
        if (contract is not None and contract.nxlog_mixed and contract.os_family != "windows"
                and "windows" in playbook.os_families):
            # NXLog's flat records on a Linux target: no Windows rule's search there is ever complete
            return [NXLOG_MIXED_GATE]
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
        if any(event.family == "database_audit" for event in required):
            # A default-instance declaration represents this SQL event shape,
            # not a requirement that a differently named instance also exist.
            # Preserve each concrete observed provider in collection evidence.
            observed_sql = [event for event in (*EVENT_CLASSES, *self._windows_dynamic_classes.get(target, ()))
                            if event.family == "database_audit" and event.token in inventory]
            expanded = {}
            for event in required:
                equivalents = [observed for observed in observed_sql
                               if event.family == "database_audit"
                               and observed.channel.casefold() == event.channel.casefold()
                               and observed.event_id == event.event_id]
                for concrete in equivalents or [event]:
                    expanded[concrete.token] = concrete
            required = list(expanded.values())
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
                    str((windows_view(record.get("_source") or {}).get("winlog") or {}).get("computer_name") or "")
                    .strip().rstrip(".").casefold(),
                    str((windows_view(record.get("_source") or {}).get("winlog") or {}).get("channel") or "").casefold(),
                )
                for record in records
            }
            observed_times: dict[tuple[str, str], tuple[datetime, datetime]] = {}
            for record in records:
                source = windows_view(record.get("_source") or {})
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
            source = windows_view(record.get("_source") or {})
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
            # an NXLog record of a catalogued provider and event id under a channel naming none of its classes
            # could be any of them: counted against their families (normalize_hits names them)
            if reason.startswith(("dataset:", "suricata event_type", NXLOG_CHANNEL_SKIP,
                                  "text line in no recognized format:", "text line too long:"))
        }

    @staticmethod
    def _unsupported_families(unsupported: dict[str, int], fed: dict[str, frozenset[str] | None]
                              ) -> tuple[frozenset[str], dict[str, int]]:
        """The families unsupported records could hide (ALL_FAMILIES when some could hold anything), and the reasons
        whose records feed no family a rule reads (Zeek logs outside the catalog): those are not assessed, and they
        make no rule's search partial."""
        families: set[str] = set()
        not_assessed = {}
        for reason, count in unsupported.items():
            known = fed.get(reason)
            if known is None:
                return ALL_FAMILIES, {}
            if known:
                families |= known
            else:
                not_assessed[reason] = count
        return frozenset(families), not_assessed

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
            if reason == RPC_REMOTE_SCOPE_SKIP or reason.startswith(("Windows event class", "duplicate Windows event copy"))
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
        if pb.id.startswith('sigma.'):
            detail = bounded_details(detail)
        return {"rule_id": pb.id, "version": pb.version, "target": target, "partition": pkey, "state": state,
                "matched": matched, "evaluated": evaluated, "detail": detail or {}}

    def _rule_failed(self, pb: Playbook, exc: Exception, where: str) -> str:
        """Record that one rule raised: it is evaluated no further in this hunt, its cells say why, and the hunt is
        partial. The exception's text is bounded and is the rule's own (typed values carry no secret)."""
        reason = (f"rule {pb.id} failed at {where}: {exc.__class__.__name__}: {str(exc)[:RULE_FAILURE_TEXT]}; "
                  f"its results from here to the end of the hunt are not computed")
        log.exception("rule %s failed at %s", pb.id, where)
        self.failed_rules.setdefault(pb.id, reason)
        self.partial_reasons.append(reason)
        self.stats.setdefault("rule_failures", {})[pb.id] = reason
        return reason

    def _failed_rule_cell(self, pb: Playbook, target: str, pkey: str, cells: list[dict]) -> None:
        """The cell of a rule that failed in this hunt: never evaluated, never a negative."""
        reason = self.failed_rules[pb.id]
        if isinstance(pb, BaselinePlaybook):
            if not self.repo.baseline_window_cell_done(self.hunt_id, pb.id, pb.version, target, pkey):
                self.repo.save_baseline_window_cell(self.hunt_id, {
                    "rule_id": pb.id, "version": pb.spec.version, "target": target, "partition": pkey,
                    "state": "evaluated_partial", "matched": 0, "evaluated": 0,
                    "detail": {"reasons": [reason], "retrieval_complete": False},
                }, ())
            return
        cells.append(self._cell(pb, target, pkey, "executed_failed", detail={"error": reason, "reasons": [reason]}))

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

    def _zeek_visibility_store(self):
        store = getattr(self, "_zeek_visibility", None)
        if store is None:
            from romulus.hunt.zeek_visibility import VisibilityStore
            directory = self._event_stage().directory
            settings = getattr(self.client, "settings", None)
            budget = StateBudget(directory, disk_total=int(
                getattr(settings,"zeek_visibility_disk_mb",256)*1024**2),
                reserve=self.budget.reserve, memory_total=2*1024**2)
            store = self._zeek_visibility = VisibilityStore(directory, budget=budget)
        return store

    def _observe_zeek_visibility(self, events):
        import sqlite3
        if getattr(self,"_zeek_visibility_failure",None):
            return
        try:
            self._zeek_visibility_store().observe(events,self.window)
        except (OSError,sqlite3.Error) as exc:
            self._zeek_visibility_failure = f"Zeek visibility state unavailable: {exc}"

    def _note_zeek_inventory_gap(self, target, contract, reasons):
        if not getattr(self,"_zeek_visibility_enabled",False):
            return
        from romulus.hunt.zeek_visibility import _Reasons
        notes = self.__dict__.setdefault("_zeek_inventory_gaps",{}).setdefault(target,_Reasons())
        for reason in reasons:
            notes.append(f"{target}: Zeek sweep inventory incomplete: {reason}"[:1024])

    def _prepare_zeek_visibility(self):
        import sqlite3

        from romulus.sources.compile import CompileError
        if hasattr(self,"_zeek_visibility_ready"):
            return
        try:
            if failure := getattr(self,"_zeek_visibility_failure",None):
                raise OSError(failure)
            self._finish_zeek_visibility()
        except (OSError,sqlite3.Error,CompileError) as exc:
            reason = f"Zeek visibility incomplete: {exc}"
            # An empty artifact can be rendered with unresolved notes without
            # another lease attempt or a database publication pointer.
            import hashlib
            digest = hashlib.sha256(b"").hexdigest()
            ref = {"sha256": digest, "filename": f"zeek-visibility-{digest}.jsonl",
                   "count": 0, "families": {}, "published": False, "complete": False}
            reason += "; this unresolved fallback publishes no visibility snapshot; zero rows do not establish healthy or complete visibility"
            self.repo.audit("system","hunt.zeek_visibility",self.hunt_id,
                            {"snapshot":ref,"notes":[],"unresolved":[reason]})
            self.repo.set_rule_cells(self.hunt_id,[
                self._cell(pb,"zeek:unresolved","visibility:"+self.window.key(),"evaluated_partial",
                    detail={"reasons":[reason],"zeek_visibility":ref})
                for pb in self.pack if set(pb.families) & _ZEEK_FAMILIES])
        self._zeek_visibility_ready = True

    def _finish_zeek_visibility(self):
        """Join source visibility once across targets before any sensor absence is stated.

        Detailed immutable rows are stored once. Rule cells carry only a sensor,
        family filter and that snapshot reference, so large hunts remain streamed.
        """
        from romulus.hunt.zeek_sources import _marker_refused, zeek_capable
        from romulus.hunt.zeek_visibility import collect_visibility
        store = getattr(self, "_zeek_visibility", None)
        if store is None:
            if self._profiles is None:
                self._profiles = self.repo.source_profiles(self.hunt_id)
            refused = any(
                any(str(key).startswith("zeek") for key in (self._profiles.get(target) or {}).get("datasets", {}))
                and any(_marker_refused(contract, log, shape) for log in ZEEK_LOGS for shape in SHAPES)
                for target,contract in self.contracts.items())
            if not refused:
                return
            store = self._zeek_visibility_store()
        policy = self.site_facts.zeek
        settings = getattr(self.client, "settings", None)
        observed = getattr(self, "_zeek_observed_targets", set())
        if self._profiles is None:
            self._profiles = self.repo.source_profiles(self.hunt_id)
        def relevant(target, contract):
            profile = self._profiles.get(target) or {}
            datasets = profile.get("datasets",{})
            if target in observed or any(str(key).startswith("zeek") for key in datasets):
                return True
            # Complete non-Zeek inventory rules out unused shared-template
            # mappings. Missing or truncated inventory cannot prove absence.
            count = profile.get("doc_count")
            unrelated = (bool(profile) and not profile.get("notes") and count is not None
                         and sum(datasets.values()) >= count)
            return zeek_capable(contract) and not unrelated
        contracts = {target: contract for target, contract in self.contracts.items() if relevant(target,contract)}
        for target,reasons in getattr(self,"_zeek_inventory_gaps",{}).items():
            if target in contracts:
                for reason in reasons:
                    store.reasons.append(reason)
        for target, contract in contracts.items():
            profile = self._profiles.get(target) or {}
            verified = target in observed or any(str(key).startswith("zeek") for key in profile.get("datasets", {}))
            if verified and any(_marker_refused(contract, log, shape) for log in ZEEK_LOGS for shape in SHAPES):
                reason = f"{target}: Zeek source markers not exact-searchable; visibility and lookback unresolved"
                store.reasons.append(reason)
                self.repo.set_rule_cells(self.hunt_id, [
                    self._cell(pb, target, "zeek-lookback", "evaluated_partial", detail={"reasons":[reason]})
                    for pb in self.pack if set(pb.families) & _ZEEK_FAMILIES])
            ranges = getattr(self, "_zeek_visibility_ranges", {}).get(target) or [self.window]
            for index, scope in enumerate(ranges):
                collect_visibility(self.client, {target:contract}, scope, store, policy,
                    heartbeat=self.heartbeat, activity=False, resolve=False,
                    max_pages=getattr(settings,"zeek_visibility_max_pages",32),
                    deadline_seconds=getattr(settings,"zeek_visibility_deadline_seconds",30),
                    health_lookahead=index == len(ranges)-1)
        store.resolve_stats(policy.stats_interval_seconds, complete=not store.reasons)
        from itertools import groupby
        ref = self.repo.save_zeek_visibility(
            self.hunt_id, store.snapshot_rows(self.window, policy.capture_loss_threshold_pct), heartbeat=self.heartbeat)
        notes = [(f"connections that began more than {policy.connection_lookback_hours:g} hours before the window "
                 "are evaluated only through Malcolm interim records; Elastic, Security Onion and plain "
                 "connections beginning earlier are not evaluated"),
                 "Malcolm diagnostic logs are not assessed: source metric fields are not verified",
                 "health interval-end lookahead is bounded to 24 hours; uncovered data intervals remain partial"]
        if warning := ref.get("cleanup_warning"):
            notes.append(warning)
        self.repo.audit("system", "hunt.zeek_visibility", self.hunt_id,
                        {"snapshot": ref, "notes": notes, "unresolved": sorted(set(store.reasons))})
        if store.reasons:
            self.repo.set_rule_cells(self.hunt_id, [
                self._cell(pb, "zeek:unresolved", "visibility:" + self.window.key(), "evaluated_partial",
                           detail={"reasons": sorted(set(store.reasons)), "zeek_visibility": ref})
                for pb in self.pack if set(pb.families) & _ZEEK_FAMILIES])
        for sensor, rows in groupby(store.summaries(), key=lambda row: row[0]):
            families = {row[1]: (bool(row[2]), row[3]) for row in rows}
            cells = []
            for pb in self.pack:
                relevant = sorted(set(pb.families) & _ZEEK_FAMILIES)
                if not relevant:
                    continue
                health = store.db.execute('SELECT partial,intervals,reason FROM sensor_health_summary WHERE sensor=?',
                                          (sensor,)).fetchone()
                partial = bool(health and health[0]) or any(
                    families[family][0] for family in set(relevant) & families.keys()) or bool(store.reasons)
                detail = {"sensor": sensor, "families": relevant, "zeek_visibility": ref,
                          "reasons": (["sensor visibility is searched in part; complete interval and analyzer "
                                       "statements are in " + ref["filename"]] if partial else []),
                          "visibility_unresolved": sorted(set(store.reasons))}
                if health:
                    detail["intervals"] = health[1]
                    if health[0]:
                        detail["reasons"].insert(0,health[2])
                cells.append(self._cell(pb, "zeek:" + sensor, "visibility:" + self.window.key(),
                                        "evaluated_partial" if partial else "evaluated_complete", detail=detail))
            self.repo.set_rule_cells(self.hunt_id, cells)

    def _zeek_conn_gap(self,target,label,reason):
        self.repo.set_rule_cells(self.hunt_id,[
            self._cell(pb,target,label,"evaluated_partial",detail={"reasons":[reason]})
            for pb in self.pack if "net_flow" in pb.families])

    def _zeek_lookback(self, target, contract, *, observed=False):
        from romulus.evidence.zeek_catalog import CONN
        from romulus.hunt.zeek_sources import overlap_groups, source_groups, zeek_capable
        if not zeek_capable(contract):
            return
        done=self.__dict__.setdefault("_zeek_lookback_done",set())
        if target in done:
            return
        if not observed:
            if self._profiles is None:
                self._profiles=self.repo.source_profiles(self.hunt_id)
            profile=self._profiles.get(target)
            # Dataset terms can omit accepted rows using another shipper marker.
            # Only a complete empty target proves absence across every representation.
            if profile is not None and profile.get("doc_count")==0 and not profile.get("notes"):
                return
        groups = [group for shape in SHAPES for group in source_groups(contract, CONN, shape)]
        if not groups:
            return
        done.add(target)
        span = Window(start=self.window.start-timedelta(hours=self.site_facts.zeek.connection_lookback_hours),
                      end=self.window.start)
        try:
            parts = plan_partitions(self.client, target, contract, span, [], groups)
            for part, count in parts:
                if count:
                    branches = [branch for shape in SHAPES for branch in overlap_groups(contract,
                        source_groups(contract,CONN,shape),self.window.start,part.end,shape=shape)]
                    self.run_partition(target, contract, [], part, count, any_of=branches)
        except (SourceError,RuntimeError) as exc:
            self._zeek_conn_gap(target,"zeek-lookback",str(exc))
        # Malcolm supplies a verified cumulative end timestamp. It can find an
        # interim whose original start lies outside the bounded start lookback.
        if (source_groups(contract, CONN, MALCOLM) and contract.supports("lastPacket", "exists")
                and contract.supports("zeek.conn.long", "in")):
            interim = contract.model_copy(update={"time_field": "lastPacket"})
            branches = [[*group, Predicate(field="zeek.conn.long", op="in", value=[True, "true"])]
                        for group in source_groups(contract, CONN, MALCOLM)]
            try:
                parts=plan_partitions(self.client, target, interim, self.window, [], branches)
                for part,count in parts:
                    if count:
                        self.run_partition(target,interim,[],part,count,any_of=branches,partition_tag="zeek-interim:")
            except (SourceError,RuntimeError) as exc:
                self._zeek_conn_gap(target,"zeek-interim-delivery",str(exc))
        elif source_groups(contract, CONN, MALCOLM):
            self._zeek_conn_gap(target,"zeek-interim-delivery",
                "interim connections older than the start lookback are unsupported: no verified searchable "
                "cumulative end timestamp and interim flag")

    def _select_ics(self, target, contract, any_of):
        from romulus.hunt.ics_filters import selection

        if self._profiles is None:
            self._profiles = self.repo.source_profiles(self.hunt_id)
        plan = selection(contract, self._profiles.get(target) or {})
        if plan.selected and any(pb.id == 'ioc.indicator_match' and (
                getattr(pb, 'ips', None) or getattr(pb, 'nets', None)
                or {'ip', 'cidr'} & getattr(getattr(pb, '_overlay', None), 'kinds', set()))
                for pb in getattr(self, 'pack', ())):
            from romulus.hunt.ics_filters import Selection

            plan = Selection(reasons=[('ICS retrieval is unfiltered to retain routine reads for active IP/CIDR '
                                      'indicator searches; polling exclusion must not hide listed contacts.')])
        self.__dict__.setdefault('_ics_selection', {})[target] = plan
        return ([[*previous, *group] for previous in any_of for group in plan.groups]
                if any_of and plan.groups else plan.groups or any_of)

    def run_target(self, target: str):
        self._zeek_visibility_enabled=True
        contract = self.contracts[target]
        self._prepare_windows_inventory(target, contract)
        self._zeek_lookback(target, contract)
        filters = self._filters_for(target, contract)
        any_of = self._any_of_for(target, contract)
        any_of = self._select_ics(target, contract, any_of)
        try:
            self.heartbeat()
            parts = plan_partitions(self.client, target, contract, self.window, filters, any_of)
            self.heartbeat()
        except Exception as e:  # noqa: BLE001 - one source failing must not hide the others
            reason = f"partition planning failed: {e}"[:300]
            self._note_zeek_inventory_gap(target,contract,[reason])
            self.partial_reasons.append(f"{target}: {reason}")
            self._mark_all(target, f"plan:{self.window.key()}", "executed_failed", {"error": reason})
            return
        if zeek_ranges := [w for w, _ in parts]:
            self.__dict__.setdefault("_zeek_visibility_ranges",{})[target] = zeek_ranges
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
                      *, estimated: bool = False, any_of: list[list[Predicate]] | None = None, partition_tag: str = ""):
        """Evaluate one partition. `est` is the histogram's exact count for a planned partition; for a half of a
        split one (`estimated`) it is only an estimate, so the half is counted before it is fetched."""
        self.heartbeat()
        splittable = (w.end - w.start) > MIN_SPLIT * 2
        if est > PARTITION_MAX_DOCS and splittable:
            # exact histogram count already exceeds the limit: subdivide before fetching anything
            a, b = self._split(target, w)
            self.run_partition(target, contract, filters, a, est // 2, estimated=True, any_of=any_of, partition_tag=partition_tag)
            self.run_partition(target, contract, filters, b, est - est // 2, estimated=True, any_of=any_of, partition_tag=partition_tag)
            return
        pkey = partition_tag + w.key()
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
            self.run_partition(target, contract, filters, a, counted // 2, estimated=True, any_of=any_of, partition_tag=partition_tag)
            self.run_partition(target, contract, filters, b, counted // 2, estimated=True, any_of=any_of, partition_tag=partition_tag)
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
            self.run_partition(target, contract, filters, a, half, estimated=True, any_of=any_of, partition_tag=partition_tag)
            self.run_partition(target, contract, filters, b, half, estimated=True, any_of=any_of, partition_tag=partition_tag)
            return
        self.stats["partitions"] += 1
        if out.completeness != Completeness.complete:
            self._note_zeek_inventory_gap(target,contract,out.reasons or [out.error or "source retrieval incomplete"])
        self.stats["records"] += out.returned
        self.repo.update_task(tid, "executed", outcome={"completeness": out.completeness, "reasons": out.reasons,
                                                        "total": out.total, "returned": out.returned})
        if out.completeness == Completeness.failed:
            self.partial_reasons.append(f"{target} {pkey}: {out.error}")
            self._mark_all(target, pkey, "executed_failed", {"error": out.error})
            self.repo.update_task(tid, "failed", error=out.error)
            return
        malformed_text: dict[str, list[str]] = {}
        skip_families: dict[str, frozenset[str] | None] = {}
        shapes: dict[str, int] = {}
        events, skips, errors = normalize_hits(out.records, self.boots, malformed_text=malformed_text,
                                               skip_families=skip_families, rpc_remote_only=True, contract=contract,
                                               surrogate_free=out.surrogate_free, shapes=shapes)
        if shapes:
            # the shipper shapes read, by target: Linux host shapes, the EVE event types an Elastic shipper indexed
            # without their line, and NXLog's flat Windows records with their collector clock offsets (one count
            # per key: each table is bounded)
            for key, count in shapes.items():
                stat = ("suricata_shapes" if key.startswith("suricata.") else
                        "windows_shapes" if key.startswith("windows.") else "linux_shapes")
                seen = self.stats.setdefault(stat, {}).setdefault(target, {})
                seen[key] = seen.get(key, 0) + count
        if errors:
            self._note_zeek_inventory_gap(target,contract,[f"{len(errors)} record normalization failures"])
        if malformed_text:
            # normalized with each lone surrogate replaced (the events name the fields): counted, never partial
            self.stats["malformed_text_records"] = self.stats.get("malformed_text_records", 0) + len(malformed_text)
        raw_sources = {f"{r['_index']}/{r['_id']}": r["_source"] for r in out.records}
        duplicate_events = []
        zeek_visibility_events = None
        windows_state_reasons: list[str] = []
        zeek_state_reasons: list[tuple[str, frozenset[str]]] = []
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
        if any(event.normalizer == ZEEK_NORMALIZER for event in events):
            if getattr(self,"_zeek_visibility_enabled",False):
                self.__dict__.setdefault("_zeek_observed_targets",set()).add(target)
                if any(event.get("zeek.log")=="conn" for event in events):
                    self._zeek_lookback(target,contract,observed=True)
            events = self._canonical_zeek(events, raw_sources, zeek_state_reasons)
            events, zeek_duplicates, zeek_superseded = self._unique_zeek(events, zeek_state_reasons)
            from romulus.hunt.zeek_connections import selection_note
            self._note_zeek_inventory_gap(target,contract,[reason for reason,_ in zeek_state_reasons
                                                           if not selection_note(reason)])
            if getattr(self,"_zeek_visibility_enabled",False):
                zeek_visibility_events = events
            duplicate_events.extend(zeek_duplicates)
            if zeek_superseded:
                skips[ZEEK_INTERIM_SUPERSEDED] = skips.get(ZEEK_INTERIM_SUPERSEDED, 0) + zeek_superseded
        if duplicate_events:
            skips["duplicate typed event across source partitions"] = len(duplicate_events)
            self.repo.merge_evidence_raw(self.hunt_id, duplicate_events, raw_sources)
        if any(event.family == "script_block" for event in events):
            assembler = self._windows_script_blocks()
            events = assembler.consume(events, raw_sources)
            raw_sources.update(assembler.sources_for(events))
            parts = [event for event in events if event.has("script.part_number")]
            if parts:
                # Part views keep every raw citation retrievable even when the joined view samples its refs.
                self.repo.save_evidence(self.hunt_id, parts, raw_sources, tid)
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
        # Records of a Zeek log the catalog names are counted against the families that log feeds; those of a Zeek
        # log outside the catalog feed none and are not assessed (the report lists every skip with its count).
        unsupported_affected, not_assessed = self._unsupported_families(unsupported, skip_families)
        if not_assessed:
            self._bounded_counts(self.stats.setdefault("not_assessed_by_target", {}).setdefault(target, {}),
                                 not_assessed)
            unsupported = {reason: count for reason, count in unsupported.items() if reason not in not_assessed}
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
        everything_unsupported = bool(unsupported) and unsupported_affected is ALL_FAMILIES
        affected = ALL_FAMILIES if (out.completeness != Completeness.complete or everything_unsupported) else set()
        # An error tag that feeds no known family could hide anything, so it affects every rule.
        error_affected: set[str] | frozenset[str] = set()
        tags = sorted({_error_tag(msg) for _rid, msg in errors})
        for tag in tags:
            fams = DATASET_FAMILIES.get(tag)
            if fams is None:
                error_affected = ALL_FAMILIES
                break
            error_affected |= fams
        if affected is not ALL_FAMILIES:
            affected = (ALL_FAMILIES if error_affected is ALL_FAMILIES
                        else set(error_affected) | (set(unsupported_affected) if unsupported else set()))
        # The reasons a cell is partial, stated on the cell so the report can list each gap with its cause.
        base_reasons = list(out.reasons)
        unsupported_reason = ""
        if everything_unsupported:
            base_reasons.append(f"unsupported_records={sum(unsupported.values())} (no normalizer; could hold any "
                                f"behavior): {'; '.join(sorted(unsupported))}")
        elif unsupported:
            unsupported_reason = (f"unsupported_records={sum(unsupported.values())} (records of a log no normalizer "
                                  f"read here; they could hold {', '.join(sorted(unsupported_affected))} records): "
                                  f"{'; '.join(sorted(unsupported))}")
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
        # a Linux target that also holds NXLog's flat Windows records is a Windows source too
        target_oses = {target_os} | ({"windows"} if contract is not None and contract.nxlog_mixed else set())
        from romulus.detect.sigma import SigmaEventIndex, SigmaRule
        sigma_index = SigmaEventIndex(events) if any(isinstance(pb, SigmaRule) for pb in self.pack) else None
        sigma_reasons = {}
        for pb in self.pack:
            if pb.id in self.failed_rules:
                self._failed_rule_cell(pb, target, pkey, cells)
                continue
            publish_errors: list[Exception] = []
            try:
                # families a rule reads only as context (its lineage) do not make a partition an evaluation of it
                evaluated_families = set(pb.families) - set(pb.context_families)
                sigma_events = sigma_index.for_rule(pb) if isinstance(pb, SigmaRule) else None
                relevant_events = (sigma_events if sigma_events is not None else
                                   [event for event in events if event.family in evaluated_families])
                target_fallback = not relevant_events and (
                    target_os == "unknown" or bool(target_oses & set(pb.os_families))
                )
                sigma_rule_reasons = []
                if sigma_events is not None:
                    reason_view = coverage_view(pb)
                    signature = reason_signature(reason_view)
                    if signature not in sigma_reasons:
                        sigma_reasons[signature] = bounded_details({'reasons': self._windows_rule_reasons(
                            target, contract, reason_view, out.records, gap_reasons, w, continuity_times)})
                    sigma_reason_detail = sigma_reasons[signature]
                    windows_reasons = visible_reasons(sigma_reason_detail)
                    sigma_rule_reasons = list(exclusion_reasons(pb))
                    windows_gate_reasons.update(sigma_reason_detail['reasons'])
                    windows_gate_reasons.update(sigma_rule_reasons)
                else:
                    windows_reasons = self._windows_rule_reasons(
                        target, contract, pb, out.records, gap_reasons, w, continuity_times,
                    )
                if (script_metadata_reasons and contract.os_family == "windows"
                        and "script_block" in pb.families):
                    windows_reasons.extend(script_metadata_reasons)
                if (script_reassembly_reasons and contract.os_family == "windows"
                        and "script_block" in pb.families):
                    windows_reasons.extend(script_reassembly_reasons)
                # Zeek dedup and interim state: only rules reading the families of the records it concerns
                windows_reasons.extend(reason for reason, fed in zeek_state_reasons if set(pb.families) & fed)
                if unsupported_reason and set(pb.families) & unsupported_affected:
                    windows_reasons.append(unsupported_reason)
                windows_gate_reasons.update(windows_reasons)
                rule_partial = (affected is ALL_FAMILIES or bool(set(pb.families) & affected)
                                or bool(windows_reasons) or bool(sigma_rule_reasons))
                input_events = events if sigma_events is None else sigma_events
                unaggregated_events = []
                identity_reason = getattr(self, "_zeek_canonical_unavailable", "")
                if identity_reason and pb.kind != "direct":
                    from romulus.hunt.zeek_connections import connection
                    uncertain = [event for event in events if connection(event) and event.family in pb.families]
                    if uncertain:
                        input_events = [event for event in events if not connection(event)]
                        if callable(getattr(pb, "consume_unaggregated", None)):
                            unaggregated_events = pb.scope_partition(uncertain)
                        else:
                            windows_reasons.append(f"{len(uncertain)} cumulative flow record(s) withheld from "
                                                   "aggregate evaluation because canonical identity state is unavailable")
                if isinstance(pb, BaselinePlaybook):
                    if self.repo.baseline_window_cell_done(
                            self.hunt_id, pb.id, pb.version, target, pkey):
                        continue
                    ordered = sorted(pb.scope_partition(input_events), key=lambda item: (
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
                scoped_events = input_events if sigma_events is not None else pb.scope_partition(input_events)
                if identity_reason and pb.kind != 'direct' and input_events is not events and not unaggregated_events:
                    withheld = sum(event.family in pb.families for event in events)-sum(
                        event.family in pb.families for event in input_events)
                    if withheld:
                        pb.refuse("source_identity", identity_reason, withheld)
                # Every rule reads every batch, whatever the state budget: a store in no-growth mode refuses only
                # records that need a new key in it (each rule's own refusal path), and every match that needs no new
                # state still publishes.
                pb.bind_raw(raw_sources, target)
                if getattr(pb, "needs_live_loader", False):
                    current_events = {event.id: event for event in events}
                    def load_live(ids, current_events=current_events):
                        missing = [identity for identity in ids if identity not in current_events]
                        return ([current_events[identity] for identity in ids if identity in current_events]
                                + self._event_stage().load(missing))
                    pb.bind_loader(load_live)
                matched = 0
                consume_failure = ""
                rule_errors: list[Exception] = []

                def consume_matches(pb=pb, scoped_events=scoped_events, before_eval=before_eval,
                                    before_missing=before_missing, before_capped=before_capped,
                                    rule_errors=rule_errors, unaggregated_events=unaggregated_events,
                                    identity_reason=identity_reason):
                    nonlocal matched, consume_failure
                    try:
                        for match in pb.consume_scoped_partition(scoped_events):
                            matched += 1
                            yield match
                        if unaggregated_events:
                            for match in pb.consume_unaggregated(unaggregated_events, identity_reason):
                                matched += 1
                                yield match
                    except StateExhausted as exc:
                        # Preserve already published matches and count the unevaluated tail even when a
                        # disk-backed replay refuses growth after yielding some observations.
                        consume_failure = (f"a write to the stage volume failed ({exc}); consume stopped before "
                                           f"completion")
                        refused_before = pb.capped
                        pb.refuse_unevaluated(scoped_events,
                                              pb.evaluated - before_eval + pb.missing_required - before_missing
                                              + pb.capped - before_capped,
                                              f"a write to the stage volume failed ({exc}); this rule's later "
                                              f"records of the batch are not evaluated")
                        if pb.capped == refused_before:
                            # Some rules count applicable records before replaying retained state. A zero
                            # unevaluated-tail count does not make an interrupted replay complete.
                            pb.note_limit("state_disk", consume_failure)
                    except INFRASTRUCTURE_ERRORS:
                        raise
                    except Exception as exc:  # noqa: BLE001 - the rule's own code; publishing is not guarded here
                        rule_errors.append(exc)

                try:
                    self._record_playbook_batch(pb, consume_matches(), raw_sources, tid, staged, held, released)
                except Exception as exc:
                    # a failure while publishing (the store, the stage, citation reads) is not the rule's defect
                    publish_errors.append(exc)
                    raise
                finally:
                    pb.bind_raw({})
                if rule_errors:
                    raise rule_errors[0]
                evaluated = pb.evaluated - before_eval
                missing = pb.missing_required - before_missing
                target_applicable = target_fallback or pb.os_applicable > before_os
                rule_partial = target_applicable and rule_partial
                if isinstance(pb, SigmaRule) and (pb._batch_argument_gap or pb._batch_unknown
                                                 or 'sigma_publication_budget' in pb.limits
                                                 or 'sigma_command_identity' in pb.limits):
                    rule_partial = True
                # records a full state budget kept from evaluation: never a clean evaluation of this partition
                capped = pb.capped - before_capped
                # records skipped or judged for a direction the default internal-network definition only assumes
                assumed = pb.direction_assumed - before_assumed
                incomplete = rule_partial or bool(missing) or bool(capped) or bool(assumed) or bool(consume_failure)
                if not target_applicable:
                    state = "not_applicable_no_events"
                elif not (evaluated_families & families) and evaluated == 0:
                    state = "not_applicable_no_events" if not rule_partial else "evaluated_partial"
                elif pb.kind == "aggregate" and matched:
                    # aggregate rules may publish indicator events during consume(); those are matches
                    state = "match_on_partial" if incomplete else "matched"
                elif pb.kind == "aggregate":
                    state = "evaluated_partial" if incomplete else "evaluated_complete"
                elif matched:
                    state = "match_on_partial" if incomplete else "matched"
                elif not (pb.assures_negative_for(scoped_events) if hasattr(pb, "assures_negative_for")
                          else pb.assures_negative):
                    # script-text rules can show intent but never prove absence (spec section 1)
                    state = "positive_only_partial" if incomplete else "positive_only"
                else:
                    state = "evaluated_partial" if incomplete else "no_match_complete"
                reasons = list(sigma_rule_reasons) if sigma_events is not None else list(base_reasons)
                if hasattr(pb, 'partition_coverage_notes'):
                    reasons.extend(pb.partition_coverage_notes())
                if sigma_events is None:
                    reasons.extend(windows_reasons)
                if consume_failure:
                    reasons.append(consume_failure)
                if error_reason and (error_affected is ALL_FAMILIES or set(pb.families) & error_affected):
                    reasons.append(error_reason)
                if missing:
                    reasons.append(f"missing_required={missing}: records lacked a field this rule needs")
                detail = {"missing_required": missing, "reasons": reasons}
                if 'ics_tx' in pb.families and (selection := getattr(self, '_ics_selection', {}).get(target)):
                    reasons.extend(selection.reasons)
                    detail['ics_retrieval_filtered'] = selection.selected
                if sigma_events is not None:
                    detail['_sigma_reason_omitted'] = sigma_reason_detail['reason_omitted']
                    detail['_sigma_reason_truncated'] = sigma_reason_detail['reason_truncated']
                    detail['undecidable_comparisons'] = sum(pb._batch_unknown.values())
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
                if sigma_events is not None:
                    reasons.extend(windows_reasons)
                    reasons.extend(base_reasons)
                cells.append(self._cell(pb, target, pkey, state, matched, evaluated, detail))
            except INFRASTRUCTURE_ERRORS:
                raise
            except Exception as exc:
                if publish_errors and exc is publish_errors[0]:
                    raise
                pb.bind_raw({})
                self._rule_failed(pb, exc, f"{target} {pkey}")
                self._failed_rule_cell(pb, target, pkey, cells)
        if windows_gate_reasons:
            self.partial_reasons.append(
                f"{target} {pkey}: " + "; ".join(sorted(windows_gate_reasons))
            )
        if staged or held or released:
            self._stage_put(list(staged.values()), raw_sources, held, released)
        staged.clear()
        if zeek_visibility_events is not None:
            self._observe_zeek_visibility(zeek_visibility_events)
        # the event stage shares the stage volume: its growth counts toward the free-space reserve
        self.budget.check_free()
        # the partition's cells together: a crash before this leaves them all visibly `planned`
        self.repo.set_rule_cells(self.hunt_id, cells)
        self.repo.update_task(tid, "evaluated")

    def _canonical_zeek(self, events, raw_sources, reasons):
        from romulus.hunt.zeek_connections import canonical
        selected = canonical(self, events, raw_sources, reasons)
        reasons[:] = list(dict.fromkeys(reasons))[:256]
        return selected

    def _unique_zeek(self, events: list[TypedEvent], reasons: list[tuple[str, frozenset[str]]]
                     ) -> tuple[list[TypedEvent], list[TypedEvent], int]:
        """Zeek records across partitions and targets: a copy of a record an earlier partition evaluated (the same
        logical id: sensor, log, connection, time and values) merges its raw reference into that event; an interim
        conn record of a connection whose later record was already evaluated is superseded. Both stores are on the
        stage volume, bounded by the hunt's state budget; a refusal is named on the rules reading what it concerns.
        Returns (events to evaluate, duplicates, superseded interim records)."""
        stage = self._event_stage()
        zeek_families = frozenset(event.family for event in events if event.normalizer == ZEEK_NORMALIZER)
        events, duplicates = stage.unique_windows(events, (ZEEK_NORMALIZER,))
        if stage.windows_refused:
            reason = (f"Zeek record dedup state refused {stage.windows_refused} event id(s): "
                      f"{stage.windows_refusal_reason}; those records were evaluated, but a copy of one in a later "
                      f"partition or target is evaluated again, so counts over them may include duplicates")
            reasons.append((reason, zeek_families))
        conn = [event for event in events if event.normalizer == ZEEK_NORMALIZER and event.get("zeek.log") == "conn"
                and event.has("zeek.uid")]
        observed = [(f"{event.host or ''}|{event.get('zeek.uid')}", event.get("conn.interim") is True)
                    for event in conn]
        if not any(interim for _key, interim in observed) and not getattr(stage, "_zeek_interim_table", False):
            return events, duplicates, 0        # no interim record has been read in this hunt
        prior, refused, why = stage.zeek_interim(observed, ZEEK_INTERIM_KEYS_LIMIT)
        superseded = {id(event) for event, (key, interim) in zip(conn, observed, strict=True)
                      if interim and prior.get(key) == 2}
        earlier = sum(1 for key, _interim in observed if prior.get(key) == 1)
        if earlier:
            reason = (f"{earlier} Zeek conn record(s) are of connections whose interim record an earlier partition "
                      f"or target already evaluated; both were evaluated, so counts over those connections may "
                      f"include both")
            reasons.append((reason, frozenset({"net_flow"})))
        if refused:
            reason = (f"the Zeek interim-record store did not keep {refused} connection(s) ({why}); a later record "
                      f"of one in another partition or target is evaluated as well, so counts over them may include "
                      f"both")
            reasons.append((reason, frozenset({"net_flow"})))
        if superseded:
            events = [event for event in events if id(event) not in superseded]
        return events, duplicates, len(superseded)

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
                account=getattr(self, "_stage_account", None),
                windows_account=getattr(self, "_windows_seen_account", None),
            )
            stage.owner_accounts = self._stage_owner_accounts
            stage.playbooks = self.pack
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
        sigma_details: dict[str, dict] = {}
        sigma_unknown: Counter[str] = Counter()
        truncation_reasons: set[str] = set()
        for batch in batched(assembler.finalize(), SCRIPT_FINALIZE_BATCH_SIZE):
            events = list(batch)
            truncation_reasons.update(
                caveat for event in events if event.get("script.truncated")
                for caveat in event.caveats if "joined text capped" in caveat
            )
            finalized += len(events)
            raw_sources = assembler.sources_for(events)
            self.repo.save_evidence(self.hunt_id, events, raw_sources, None)
            staged: dict[str, TypedEvent] = {}
            held: list[tuple[str, TypedEvent]] = []
            released: list[tuple[str, list[str]]] = []
            for pb in self.pack:
                if (isinstance(pb, BaselinePlaybook) or "script_block" not in pb.families
                        or pb.id in self.failed_rules):
                    continue
                scoped = pb.scope_partition(events)
                if not scoped:
                    continue
                evaluated[pb.id] += len(scoped)
                pb.bind_raw(raw_sources, "script-block-finalize")
                if pb.id.startswith('sigma.') and getattr(pb, 'needs_live_loader', False):
                    current = {event.id: event for event in events}
                    def load_script(ids, current=current):
                        missing = [identity for identity in ids if identity not in current]
                        return ([current[identity] for identity in ids if identity in current]
                                + self._event_stage().load(missing))
                    pb.bind_loader(load_script)
                try:
                    matches = pb.consume_scoped_partition(scoped)
                except StateExhausted as exc:
                    pb.note_limit("script_reassembly", f"incomplete script blocks were not evaluated ({exc})")
                    matches = []
                except INFRASTRUCTURE_ERRORS:
                    raise
                except Exception as exc:  # noqa: BLE001 - one rule's defect must not cost the other rules
                    self._rule_failed(pb, exc, "script-block finalize")
                    continue
                finally:
                    pb.bind_raw({})
                matched[pb.id] += len(matches)
                if pb.id.startswith('sigma.'):
                    detail = sigma_details.get(pb.id, {'reasons': []})
                    detail['reasons'] = [*detail['reasons'], *pb.partition_coverage_notes()]
                    sigma_details[pb.id] = bounded_details(detail)
                    sigma_unknown[pb.id] += sum(pb._batch_unknown.values())
                self._record_playbook_batch(pb, matches, raw_sources, None, staged, held, released)
            if staged or held or released:
                self._stage_put(list(staged.values()), raw_sources, held, released)
            self.budget.check_free()
        if not finalized:
            return
        reason = f"PowerShell script-block reassembly incomplete for {finalized} block(s); missing parts stated"
        if truncation_reasons:
            reason += "; " + "; ".join(sorted(truncation_reasons))
        self.partial_reasons.append(reason)
        for pb in self.pack:
            if not evaluated[pb.id]:
                continue
            detail = {'reasons': [reason]}
            if pb.id.startswith('sigma.'):
                detail = dict(sigma_details.get(pb.id, {'reasons': []}))
                detail['reasons'] = [*detail['reasons'], reason]
                detail['undecidable_comparisons'] = sigma_unknown[pb.id]
                detail = bounded_details(detail)
            self.repo.set_rule_cell(
                self.hunt_id, pb.id, pb.version, "script-block-finalize", "incomplete",
                "match_on_partial" if matched[pb.id] else "evaluated_partial",
                matched[pb.id], evaluated[pb.id], detail,
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
        sources = stage.raw_sources(match.events)
        from romulus.hunt.citations import COMPACT_CITATION_NOTE
        for event in match.events:
            if any(ref.key not in sources for ref in event.raw) and COMPACT_CITATION_NOTE not in event.caveats:
                event.caveats.append(COMPACT_CITATION_NOTE)
        return sources

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
            finalized_matches = 0
            if pb.id not in self.failed_rules:
                # Only the rule's own code is guarded. Publishing (the store, citation reads from the source) is
                # outside the guard, so its failures end the sweep and are never recorded as the rule's defect.
                try:
                    matches = iter(self._finalize_rule(pb))
                except INFRASTRUCTURE_ERRORS:
                    raise
                except Exception as exc:  # noqa: BLE001 - one rule's defect must not cost the other rules
                    self._rule_failed(pb, exc, "finalize")
                    matches = iter(())
                while True:
                    try:
                        m = next(matches)
                    except StopIteration:
                        break
                    except INFRASTRUCTURE_ERRORS:
                        raise
                    except Exception as exc:  # noqa: BLE001 - one rule's defect must not cost the other rules
                        self._rule_failed(pb, exc, "finalize")
                        break
                    finalized_matches += 1
                    raw_sources = ({**agg_raw, **self._merge_staged_match_raw(m)} if pb.staged else agg_raw)
                    self._publish(m, None, raw_sources)
            if pb.id in self.failed_rules:
                reason = self.failed_rules[pb.id]
                published = f"{finalized_matches} finding(s) of this rule published at finalize before it failed"
                self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, "*", "window", "executed_failed",
                                        finalized_matches, 0, {"error": reason, "reasons": [reason, published]})
                if getattr(self, "_stage", None) is not None and pb.id in self._stage_owner_accounts:
                    self._stage.finished_owners.add(self._stage_owner_accounts[pb.id].name)
                pb.release_state()
                continue
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
            matched_any = finalized_matches > 0 or consumed_matches > 0
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
            detail = {'reasons': reasons}
            if pb.id.startswith('sigma.'):
                detail = bounded_details(detail)
            self.repo.set_rule_cell(self.hunt_id, pb.id, pb.version, "*", "window", state,
                                    finalized_matches + consumed_matches, evaluated, detail)
            if getattr(self, "_stage", None) is not None and pb.id in self._stage_owner_accounts:
                self._stage.finished_owners.add(self._stage_owner_accounts[pb.id].name)
            pb.release_state()
        agg_raw.clear()
        self._prepare_zeek_visibility()
        # Visibility completes after every finding has been published. Reflect
        # its sensor cells in whole-window rollups without rerunning any rule.
        for pb in self.pack:
            if not (set(pb.families) & _ZEEK_FAMILIES):
                continue
            cells = self.repo.rule_cells(self.hunt_id, rule_id=pb.id)
            if not any(c["target"].startswith("zeek:") and c["state"] == "evaluated_partial" for c in cells):
                continue
            for cell in cells:
                if cell["target"] == "*" and cell["partition"] == "window" and cell["state"] != "executed_failed":
                    state = "match_on_partial" if cell["matched"] else "evaluated_partial"
                    detail = dict(cell["detail"] or {})
                    detail["reasons"] = list(dict.fromkeys([*detail.get("reasons",[]), WINDOW_ROLLUP_PARTIAL]))
                    if pb.id.startswith('sigma.'):
                        detail = bounded_details(detail)
                    self.repo.set_rule_cell(self.hunt_id,pb.id,pb.version,"*","window",state,
                        cell["matched"],cell["evaluated"],detail)
        if self.budget.spent:
            self.partial_reasons.append(f"state budget: {self.budget.spent}")
            self.stats["state_budget"] = {"spent": self.budget.spent, "disk_bytes": self.budget.disk_used,
                                          "disk_total": self.budget.disk_total, "reserve": self.budget.reserve,
                                          "floor": self.budget.floor, "shared": self.budget.pool,
                                          "shared_used": self.budget.pool_used,
                                          "stores_without_new_keys": sorted(self.budget.full)}
        self.close_stage()

    @staticmethod
    def _finalize_rule(pb: Playbook):
        """A rule's finalize. When it needs disk the stage volume cannot give, the rule publishes what it can from
        state readable without writing (`finalize_fallback`: strong per-record items), and its window cell says
        which results were not computed (the hunt goes on)."""
        from romulus.detect.correlation import StageMissing
        def fallback(exc):
            pb.note_limit("state_disk", f"finalize stopped: {exc}; this rule's groupings were not computed, only "
                                        f"what it could publish without disk")
            try:
                return pb.finalize_fallback(str(exc))
            except (StateExhausted, StageMissing, LookupError):
                return []
        try:
            matches = pb.finalize()
        except (StateExhausted, StageMissing, LookupError) as exc:
            return fallback(exc)
        if isinstance(matches, (list, tuple)):
            return matches

        def stream():
            try:
                yield from matches
            except (StateExhausted, StageMissing, LookupError) as exc:
                yield from fallback(exc)
        return stream()

    def close_stage(self) -> None:
        """Remove the disk stage, Windows continuity state and playbook spills on every controlled exit path."""
        visibility = getattr(self, "_zeek_visibility", None)
        if visibility is not None:
            visibility.close()
            self._zeek_visibility = None
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
            # These closed private files remained billed until their containing stage directory was removed.
            for store in (continuity, scripts):
                if store is not None and store.account is not None:
                    self.budget.release_physical_account(store.account)
        for pb in getattr(self, "pack", ()):
            pb.close_spill()
