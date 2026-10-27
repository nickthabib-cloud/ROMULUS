"""Shared machinery for Windows process-creation rules.

ROMULUS finds what is present and never asserts that nothing is present, so every rule here is positive-only: a
window without a match is never a complete negative. Coverage cells still record what was searched and what was
not (inventory, shipper completeness and unattested collection stay in the cell reasons); they never become
``no_match_complete``.

- Program identity comes from the OS-recorded image path (`process.executable_key`,
  `process.parent.executable_key`): its last component, compared case-insensitively. Directory prefixes (`C:\\`,
  `\\Device\\HarddiskVolumeN\\`, `\\\\?\\`), System32 versus SysWOW64 and the drive letter never matter. An image
  whose last component is an 8.3 short name (`POWERS~1.EXE`) cannot be identified without guessing, so the record
  is undecided (counted, the cell is partial), never judged benign.
- Parent resolution, and when a finding is published:
  - a child whose own record names its parent image (Sysmon 1 `ParentImage`; Security 4688 `ParentProcessName` once
    typed) is judged and published immediately: that answer can never change;
  - otherwise `WindowsPidLineage` resolves the parent from its own creation record: the latest recorded creation of
    the parent's pid on that host at or before the child, with no recorded termination (4689, Sysmon 5) after it and
    before the child, and no boot between. When that is decided at observation time the child is judged and
    published immediately too, and it is watched: a creation or termination of that pid that arrives later (a late
    shipment, another target swept later) and falls inside the child's window marks it for re-judgement at
    finalize. If the re-judged answer differs, a correction finding is published that names what changed and why,
    at the lane the corrected evidence supports (a lead when the parent is no longer resolved). Findings are never
    deleted and never moved to context;
  - a child whose parent cannot be decided at observation time (pid not yet seen, an unorderable same instant, a
    fence or boot that a later record could still explain) is deferred and judged at finalize against the complete
    history.
  Every child on the pid path is handed to the sweep's event stage (one copy, shared by every rule), so it can be
  re-read and cited at finalize; the parent creation records a finding cites carry their raw copies with the match.
- Fleet handling (never hides a match or an attacker's payload): the group key is the distinguishing content
  (behaviour, image, parent image, normalized command line, decoded payload); the first record of each (shape, host)
  is a finding of its own; only repeats on an already-reported host merge. Published candidates are stored once per
  id (a later publish of the same id does not overwrite it), so the merged finding published at the first repeat is
  worded as a lower bound that stays true, and the exact tally is a separate summary published when the sweep ends.
- Groups, membership, process history and watches live in disk-backed stores; only a spent disk budget refuses, and
  then the record is published on its own and coverage says so.
"""
from __future__ import annotations

import hashlib
import ntpath
import re
from bisect import insort
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import Match, Playbook, PredicateField
from romulus.detect.bounded import HOT_COUNT, HeldExamples, KeyedStore, RecentIds
from romulus.detect.citing import BoundStage, Ends, bound_note, cite_group, cited_phrase
from romulus.detect.host import add_unheld, alone, exec_order
from romulus.detect.windows_cmdline import PARSED
from romulus.evidence.typed import TypedEvent
from romulus.evidence.windows_catalog import SECURITY, SYSMON, SYSMON_CHANNEL

SYSMON_PROCESS_CREATE = (SYSMON_CHANNEL, SYSMON, 1)
SECURITY_PROCESS_CREATE = ("Security", SECURITY, 4688)
# Fence families the parent-resolving rules read as context (never an evaluation of the rule).
FENCE_FAMILIES = ("process_termination", "system_state")

_SHORT_NAME = re.compile(r"^[^.~\\]{1,6}~\d+(?:\.[^.\\]{0,3})?$")
_LANE_RANK = {"urgent": 0, "high": 1, "lead": 2, "context": 3}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CLAIM_TEXT_LIMIT = 300
FLEET_HOST_SAMPLE = 20
# Undecided parent kinds a later record could still change (the child is deferred to finalize, never counted now).
_DEFERRABLE = frozenset({"parent_unrecorded", "parent_order", "parent_ended", "parent_boot", "parent_image"})

# Programs that run code they are handed: command shells, PowerShell, script hosts and the signed binaries most used
# to proxy execution or fetch and decode payloads. Shared by the parent/child rules.
SHELLS_AND_SCRIPT_HOSTS = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "bash.exe", "wsl.exe",
})
PROXY_BINARIES = frozenset({
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "schtasks.exe", "wmic.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "hh.exe", "forfiles.exe",
    "curl.exe", "msxsl.exe", "odbcconf.exe", "scriptrunner.exe", "mavinject.exe", "msdt.exe", "control.exe",
    "pcalua.exe", "infdefaultinstall.exe", "presentationhost.exe", "ieexec.exe", "csc.exe", "vbc.exe", "jsc.exe",
    "certoc.exe", "esentutl.exe", "expand.exe", "extrac32.exe", "finger.exe", "ftp.exe", "regini.exe",
    "reg.exe", "sc.exe", "net.exe", "net1.exe", "netsh.exe", "vssadmin.exe", "wevtutil.exe", "bcdedit.exe",
})
SPAWNED_CODE_RUNNERS = SHELLS_AND_SCRIPT_HOSTS | PROXY_BINARIES


def image_name(key: object) -> tuple[str | None, str]:
    """(casefolded last component of an image path key, '' ) or (None, why it cannot be identified)."""
    if key in (None, ""):
        return None, "image path not recorded"
    text = str(key).replace("/", "\\").rstrip("\\")
    name = ntpath.basename(text).casefold()
    if not name:
        return None, "image path has no file name"
    if _SHORT_NAME.match(name):
        return None, f"image file name '{name}' is an 8.3 short name"
    return name, ""


def in_windows_system_dir(key: object) -> bool:
    """Whether an image path key is directly in Windows\\System32, SysWOW64 or Sysnative, on any volume prefix."""
    parts = [part for part in str(key or "").casefold().replace("/", "\\").split("\\") if part]
    return len(parts) >= 3 and parts[-3] == "windows" and parts[-2] in {"system32", "syswow64", "sysnative"}


def event_source(event: TypedEvent) -> str:
    code = event.get("event.code")
    if code == 1:
        return "Sysmon event 1"
    if code == 4688:
        return "Security event 4688"
    return f"event {code}"


def clip(text: object, limit: int = CLAIM_TEXT_LIMIT) -> str:
    value = str(text or "")
    return value if len(value) <= limit else value[:limit] + f"... ({len(value):,} characters in all)"


def parsed_field(event: TypedEvent, value: object, name: str = "process.command_line") -> PredicateField:
    """A predicate value read out of a typed text field by the command-line parser."""
    origin = event.fields[name].origin
    return PredicateField(field=name, value=value, origin=f"{origin}{PARSED}")


def typed_field(event: TypedEvent, name: str) -> PredicateField:
    item = event.fields[name]
    return PredicateField(field=name, value=item.value, origin=item.origin)


def _normalized(text: object) -> str:
    return " ".join(str(text or "").casefold().split())


def _has_recorded_parent(event: TypedEvent) -> bool:
    return event.get("process.parent.executable_key") not in (None, "")


class Undecided(Exception):
    """The record cannot be judged by this rule (a field is missing or ambiguous); counted, never a no-match."""

    def __init__(self, kind: str, text: str):
        super().__init__(text)
        self.kind = kind
        self.text = text


# ---- parent resolution by process id --------------------------------------------------------------------------------

@dataclass(frozen=True)
class ParentImage:
    key: str
    name: str
    event_id: str            # the parent's creation record (typed event id)
    native_id: str           # its first raw record's native id
    ts: float
    resolved_by: str         # "record" (the child's own field) | "pid" (the parent's own creation record)
    event: TypedEvent | None = None            # the parent's creation event, for citation (pid resolution only)
    raw_copies: tuple = ()                     # ((key, source), ...) of that record, carried with the match


def _order_of(event: TypedEvent) -> tuple[int | None, object | None]:
    return exec_order(event)


def _before(order_a, ts_a, order_b, ts_b) -> int | None:
    """-1/0/1 comparing (ts, in-sequence record id) of A against B; None when a same-instant pair cannot be ordered
    (their record ids are in different computer/channel sequences, or one is missing)."""
    if ts_a < ts_b:
        return -1
    if ts_a > ts_b:
        return 1
    serial_a, domain_a = order_a
    serial_b, domain_b = order_b
    if serial_a is None or serial_b is None or domain_a is None or domain_a != domain_b:
        return None
    return (serial_a > serial_b) - (serial_a < serial_b)


@dataclass
class _ProcEntry:
    """One recorded process-lifecycle event of a (host, pid): a creation ("exec") or a termination ("term"). Compact:
    the full record is kept only for creations of images a rule can cite as a parent (`WindowsPidLineage.cites`)."""
    ts: float
    serial: int | None
    domain: object
    kind: str                       # "exec" | "term"
    image: str = ""
    event_id: str = ""
    native_id: str = ""

    @property
    def order(self) -> tuple:
        return (self.serial, self.domain)

    def sort_key(self) -> tuple:
        return (self.ts, self.serial is None, self.serial or 0, repr(self.domain), self.kind, self.event_id)


class WindowsPidLineage:
    """One shared, time-ordered history, for every parent-resolving rule, of the creation and termination records of
    each (host, pid), and the boots of each host.

    It never forgets: entries are appended per (host, pid) in order and the whole history is kept, spilling to disk
    when cold (only the disk budget may refuse a new key, and that refusal is stated). Entries are compact; the full
    record and its raw copy are kept only for creations of images some rule cites as a parent (`interest`). A lookup
    asks which exec of the pid was live at the child's time with no fence between, so the answer is exact whatever the
    arrival order and whichever rule asks. Records of one instant are ordered only inside one computer/channel record-id
    sequence; anything else stays undecided.

    It also keeps the watches of children judged on the pid path: a creation or termination of a watched child's
    parent pid that arrives after the child was judged, at or before the child's time, marks that child dirty, so its
    rules re-judge it at finalize."""

    def __init__(self, owner, members: list | None = None, interest: frozenset[str] = frozenset()):
        self.procs: KeyedStore = KeyedStore(owner, "win_pid_history", HOT_COUNT)
        self.boots: KeyedStore = KeyedStore(owner, "win_boot_history", HOT_COUNT)
        self.cites: KeyedStore = KeyedStore(owner, "win_parent_cites", HOT_COUNT)       # event id -> (event, raw)
        self.watch: KeyedStore = KeyedStore(owner, "win_child_watch", HOT_COUNT)        # (host, ppid) -> [(ts, id)]
        self.dirty: KeyedStore = KeyedStore(owner, "win_child_dirty", HOT_COUNT)        # child id -> 1
        self.members = members if members is not None else [owner]
        self.interest = frozenset(interest)
        self._seen = RecentIds()
        self._watched = RecentIds()
        self.refused_keys = RecentIds()
        self.incomplete = False
        # Rules holding this history that have not yet released it. The sweep finalizes and releases rules one by
        # one, so the history is cleared only when its last holder releases: every holder's finalize reads it whole.
        self._holding = {id(member) for member in self.members}

    def _stores(self) -> tuple[KeyedStore, ...]:
        return (self.procs, self.boots, self.cites, self.watch, self.dirty)

    def trim(self) -> None:
        for store in self._stores():
            store.trim()

    def clear(self) -> None:
        for store in self._stores():
            store.clear()

    def release(self, holder) -> None:
        """A holder lets go of the history (a second release by the same holder counts once); it is cleared when no
        holder is left."""
        self._holding.discard(id(holder))
        if not self._holding:
            self.clear()

    def _refused(self, what: str) -> None:
        self.incomplete = True
        for member in self.members:
            member.note_limit("win_pid_history", f"the shared Windows process-history store took no new {what} (its "
                                                 f"share of the state budget is spent); a later parent lookup that "
                                                 f"needs it is undecided")

    def observe(self, event: TypedEvent, raw: dict[str, dict] | None = None) -> None:
        seen = (event.id, event.ts)
        if seen in self._seen:          # the same record handed over again (another rule, or a re-read/resume)
            return
        self._seen.add(seen)
        ts = event.ts.timestamp()
        if event.family == "system_state":
            if event.get("process.fence") != "boot" or event.get("system.event") != "boot_start":
                return
            boots = self.boots.get(event.host)
            if boots is None:
                if not self.boots.put(event.host, [ts]):
                    self.refused_keys.add(f"boot:{event.host}")
                    self._refused("host")
                return
            if ts not in boots:
                boots.append(ts)
                boots.sort()
            return
        pid = event.get("process.pid")
        if not isinstance(pid, int) or isinstance(pid, bool):
            return
        kind = "exec" if event.family == "process_exec" else "term" if event.family == "process_termination" else None
        if kind is None:
            return
        serial, domain = _order_of(event)
        entry = _ProcEntry(ts, serial, domain, kind)
        if kind == "exec":
            entry.image = str(event.get("process.executable_key") or "")
            entry.event_id = event.id
            entry.native_id = event.raw[0].native_id if event.raw else ""
            if image_name(entry.image)[0] in self.interest and not self.cites.put(
                    event.id, (event, tuple(sorted((raw or {}).items())))):
                for member in self.members:
                    member.note_limit("win_parent_cites", "the store of parent creation records kept for citation "
                                                          "took no new record; a finding that names such a parent "
                                                          "says its record is not cited")
        key = (event.host, pid)
        entries = self.procs.get(key)
        if entries is None:
            if not self.procs.put(key, [entry]):
                self.refused_keys.add(f"pid:{event.host}:{pid}")
                self._refused("process")
                return
        else:
            insort(entries, entry, key=_ProcEntry.sort_key)
        self._mark_late(key, ts, (serial, domain), event, raw)

    # The late records kept per dirty child, cited by a revision (the first few; the claim says how many arrived).
    LATE_RECORDS_KEPT = 4

    def _mark_late(self, key: tuple, ts: float, order: tuple, event: TypedEvent, raw: dict | None) -> None:
        """A record of pid `key` arrived: every child already judged against that pid whose time is at or after it
        may now have a different parent, so it is re-judged at finalize. The record itself (with its raw copy) is
        kept with the child, so a revision can cite the evidence that changed the answer."""
        watched = self.watch.get(key)
        if not watched:
            return
        for child_ts, child_serial, child_domain, child_id in watched:
            relation = _before(order, ts, (child_serial, child_domain), child_ts)
            if relation is None or relation <= 0:
                late = self.dirty.get(child_id)
                if late is None:
                    late = [0, []]
                    if not self.dirty.put(child_id, late):
                        for member in self.members:
                            member.note_limit("win_child_dirty", "the store of children to re-judge took no new "
                                                                 "child; a later record that changes such a child's "
                                                                 "parent is not applied to it")
                        continue
                late[0] += 1
                if len(late[1]) < self.LATE_RECORDS_KEPT:
                    late[1].append((event, tuple(sorted((raw or {}).items()))))
                self.dirty.put(child_id, late)

    def late_records(self, child_id: str) -> tuple[int, list[tuple[TypedEvent, dict]]]:
        """(how many late records of the parent pid fell inside the child's window, the first few with raw copies)."""
        late = self.dirty.peek(child_id)
        if not late:
            return 0, []
        return int(late[0]), [(event, dict(raw)) for event, raw in late[1]]

    def watch_child(self, child: TypedEvent) -> None:
        """Watch a child judged on the pid path (once, however many rules judge it)."""
        ppid = child.get("process.ppid")
        if not isinstance(ppid, int) or isinstance(ppid, bool) or child.id in self._watched:
            return
        self._watched.add(child.id)
        serial, domain = _order_of(child)
        key = (child.host, ppid)
        record = (child.ts.timestamp(), serial, domain, child.id)
        watched = self.watch.get(key)
        if watched is None:
            if not self.watch.put(key, [record]):
                for member in self.members:
                    member.note_limit("win_child_watch", "the store of watched children took no new parent pid; a "
                                                         "later record that would correct such a child is not "
                                                         "applied to it")
            return
        watched.append(record)

    def dirty_ids(self) -> list[str]:
        return sorted(str(key) for key in self.dirty.keys())  # noqa: SIM118 (a KeyedStore, keys on disk too)

    def parent(self, child: TypedEvent) -> ParentImage:
        """The image of the process that held the child's parent pid when the child was created: the latest recorded
        exec of that pid at or before the child with no termination between it and the child and no boot between.
        Raises Undecided (never a benign/no-match) when it cannot be decided."""
        ppid = child.get("process.ppid")
        if not isinstance(ppid, int) or isinstance(ppid, bool):
            raise Undecided("parent_pid", "the parent process id is not recorded")
        if ppid in (0, 4):
            return ParentImage("system", "system", "", "", 0.0, "pid")
        key = (child.host, ppid)
        if f"pid:{child.host}:{ppid}" in self.refused_keys or (self.incomplete and key not in self.procs):
            raise Undecided("parent_refused", "the shared process-history store refused the parent's history")
        entries = self.procs.get(key)
        child_ts = child.ts.timestamp()
        child_order = _order_of(child)
        if not entries:
            raise Undecided("parent_unrecorded", "no creation of the parent's process id is recorded on this host at "
                                                 "or before the child (the parent may predate the hunt window)")
        execs = [entry for entry in entries if entry.kind == "exec"]
        for exec_entry in sorted(execs, key=_ProcEntry.sort_key, reverse=True):
            rel = _before(exec_entry.order, exec_entry.ts, child_order, child_ts)
            if rel is None:
                raise Undecided("parent_order", "the parent's creation record and the child share an instant and "
                                                "cannot be ordered outside one computer/channel record-id sequence")
            if rel > 0:
                continue                                    # this exec is after the child: not the parent
            for term in entries:
                if term.kind != "term":
                    continue
                after_exec = _before(exec_entry.order, exec_entry.ts, term.order, term.ts)
                before_child = _before(term.order, term.ts, child_order, child_ts)
                if after_exec is not None and after_exec < 0 and before_child is not None and before_child <= 0:
                    raise Undecided("parent_ended", "the process that held the parent's id terminated after its "
                                                    "recorded creation and before the child, so no live parent is "
                                                    "recorded")
            boots = self.boots.get(child.host) or []
            if any(exec_entry.ts < boot <= child_ts for boot in boots):
                raise Undecided("parent_boot", "a boot of the host lies between the parent id's recorded creation and "
                                               "the child, so the recorded creation is from an earlier boot")
            name, why = image_name(exec_entry.image)
            if name is None:
                raise Undecided("parent_image", f"the parent's image cannot be identified: {why}")
            kept = self.cites.peek(exec_entry.event_id) if name in self.interest else None
            event, raw = (kept if kept is not None else (None, ()))
            return ParentImage(exec_entry.image, name, exec_entry.event_id, exec_entry.native_id, exec_entry.ts,
                               "pid", event, tuple(raw))
        raise Undecided("parent_unrecorded", "no creation of the parent's process id is recorded at or before the "
                                             "child, so the parent's own creation is not recorded")


def parent_predicate(event: TypedEvent, parent: ParentImage
                     ) -> tuple[list[PredicateField], list[TypedEvent], str, dict[str, dict]]:
    """Predicate fields for a resolved parent, the records to cite, how the parent was resolved, and the raw copies
    the rule carries for a cited record the sweep's partition does not hold. A parent named in the child's own record
    is that record's field. A parent resolved by pid is carried as a predicate field whose origin points at its own
    creation record, which is cited with its raw copy."""
    predicate = [typed_field(event, "process.executable_key")]
    if parent.resolved_by == "record":
        predicate.append(typed_field(event, "process.parent.executable_key"))
        return predicate, [], "its own image field", {}
    origin = (f"{parent.native_id}:lineage:process.parent.executable_key" if parent.native_id
              else f"{parent.event_id}:lineage:process.parent.executable_key")
    predicate.append(PredicateField(field="process.parent.executable_key", value=parent.key, origin=origin))
    context = [parent.event] if parent.event is not None else []
    how = "its own creation record, matched by process id"
    if parent.event is None and parent.event_id:
        how += " (that record was not kept for citation)"
    return predicate, context, how, dict(parent.raw_copies)


def resolve_parent(event: TypedEvent, lineage: WindowsPidLineage | None) -> ParentImage:
    """The parent image of a process-creation record: its own typed field when present (Sysmon 1 `ParentImage`,
    Security 4688 `ParentProcessName`), used and cited from the child record; else the shared pid lineage."""
    key = event.get("process.parent.executable_key")
    if key not in (None, ""):
        name, why = image_name(key)
        if name is None:
            raise Undecided("parent_image", f"the parent's image cannot be identified: {why}")
        return ParentImage(str(key), name, event.id, "", event.ts.timestamp(), "record")
    if lineage is None:
        raise Undecided("parent_image", "the parent's image is not recorded")
    return lineage.parent(event)


def share_windows_lineage(pack: list) -> None:
    """Give every parent-resolving Windows rule in a pack one shared `WindowsPidLineage` (observed once, held once),
    keeping full parent records for the union of the images those rules cite as parents."""
    holders = [pb for pb in pack if isinstance(getattr(pb, "lineage", None), WindowsPidLineage)]
    if len(holders) < 2:
        return
    interest = frozenset().union(*(getattr(pb, "parent_images", frozenset()) for pb in holders))
    shared = WindowsPidLineage(holders[0], holders, interest)
    for pb in holders:
        pb.lineage = shared


# ---- the rule base ----------------------------------------------------------------------------------------------

@dataclass
class Hit:
    """One behaviour a record shows: its wording, lane and severity, and the predicate values it rests on.

    `content` is the distinguishing payload used (with the command line, image and parent) to key the fleet group,
    so two different payloads are never merged. `common` is the wording a fleet finding uses for what members share.
    `raw_copies` carries the raw records of cited context (a pid-resolved parent's creation record).
    """
    behavior: str
    text: str
    lane: str
    severity: str
    attack: tuple[str, ...]
    predicate: list[PredicateField]
    confidence: str = "high"
    content: str = ""
    common: str = ""
    notes: tuple[str, ...] = ()
    context: list[TypedEvent] = field(default_factory=list)
    raw_copies: dict = field(default_factory=dict)
    parent_name: str = ""


@dataclass
class _Group:
    """One repeating shape across the fleet: what its members share, counts, member hosts and cited records."""
    behavior: str
    common: str
    lane: str
    severity: str
    attack: tuple[str, ...]
    predicate: list[tuple]
    hosts: int = 0
    records: int = 0
    repeats: int = 0
    emitted_records: int = 0
    sample_hosts: list = field(default_factory=list)
    ends: Ends = field(default_factory=Ends)
    examples: HeldExamples = field(default_factory=lambda: HeldExamples(8))
    # members a later record of their parent pid withdrew (taken out of the counts), the ids of those that were
    # held examples (cited as context of the final tally, at most WITHDRAWN_CITED), and of those that bound the
    # stated interval (at most two; never counted as a remaining member)
    excluded: int = 0
    withdrawn: list = field(default_factory=list)
    withdrawn_bounds: list = field(default_factory=list)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__.update({"excluded": 0, "withdrawn": [], "withdrawn_bounds": []})
        self.__dict__.update(state)


WITHDRAWN_CITED = 4


def _late_phrase(item: TypedEvent) -> str:
    what = "a termination" if item.family == "process_termination" else "a creation"
    return f"{what} of pid {item.get('process.pid')} at {item.ts.isoformat()}"


def _signature(hits: list[Hit]) -> tuple:
    """What a rule decided about one child, for comparing an early judgement with the finalize re-judgement."""
    return tuple(sorted((hit.behavior, hit.lane, hit.severity, hit.parent_name) for hit in hits))


class WindowsProcessRule(Playbook):
    """A positive-only rule judged on one Windows process-creation record at a time (see the module notes)."""

    os_families = ("windows",)
    families: ClassVar[tuple[str, ...]] = ("process_exec",)
    kind = "aggregate"
    staged = True
    state_slice = "strong"
    claim_type = "observed_action"
    windows_event_classes = (SYSMON_PROCESS_CREATE, SECURITY_PROCESS_CREATE)
    assures_negative = False
    positive_only_reason = ("ROMULUS reports what it finds and never asserts that a behaviour did not occur: absence "
                            "cannot be confirmed from process-creation records, and the same behaviour can be reached "
                            "by images, binaries and arguments this rule does not enumerate")
    reads_command_line: ClassVar[bool] = True
    uses_parent: ClassVar[bool] = False
    # Parent images this rule can cite (their creation records are kept for citation by the shared lineage).
    parent_images: ClassVar[frozenset[str]] = frozenset()
    HOT = HOT_COUNT

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # A parent-resolving rule must read process terminations and boots so the pid lineage sees its fences; the
        # sweep retrieves them because they are in `families`, and they are context (a partition of only fences is
        # no evaluation of the rule) and never in `windows_event_classes`.
        if getattr(cls, "uses_parent", False):
            fences = tuple(f for f in FENCE_FAMILIES if f not in cls.families)
            if fences:
                cls.families = tuple(cls.families) + fences
            cls.context_families = tuple(dict.fromkeys(tuple(cls.context_families) + FENCE_FAMILIES))

    def __init__(self):
        super().__init__()
        self.groups: KeyedStore = KeyedStore(self, "fleet_groups", self.HOT)
        self.members_store: KeyedStore = KeyedStore(self, "fleet_members", self.HOT)   # (shape, host) -> [count]
        self.order: KeyedStore = KeyedStore(self, "fleet_order", self.HOT)             # shape -> 1, in first order
        self.bounds = BoundStage()
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self._seen = RecentIds()
        self.lineage: WindowsPidLineage | None = (WindowsPidLineage(self, interest=self.parent_images)
                                                  if self.uses_parent else None)
        self.undecided: dict[str, int] = {}
        # pid-path children this rule could not decide at observation time (ids; the records wait in the sweep's
        # event stage), and the early pid-path judgements that produced a finding (child id -> signature), to be
        # compared with the finalize re-judgement of a child a late record marked dirty.
        self.deferred: KeyedStore | None = (KeyedStore(self, "parent_deferred", self.HOT)
                                            if self.uses_parent else None)
        self.early: KeyedStore | None = KeyedStore(self, "parent_early", self.HOT) if self.uses_parent else None
        self.load = lambda ids: []

    # ---- sweep protocol ----
    def drain_staged(self) -> list[TypedEvent]:
        out, self._pending = self._pending + self.bounds.drain(), []
        for store in self._fresh:
            store.staged()
        self._fresh = []
        self._trim()
        return out

    def drain_bounds(self) -> tuple[list[str], list[str]]:
        return self.bounds.last

    def retained_events(self) -> list[TypedEvent]:
        return []

    def _owned_stores(self) -> list:
        stores = [self.groups, self.members_store, self.order]
        stores += [store for store in (self.deferred, self.early) if store is not None]
        return stores

    def _trim(self) -> None:
        for store in self._owned_stores():
            store.trim()
        if self.lineage is not None:
            self.lineage.trim()

    def release_state(self) -> None:
        for store in self._owned_stores():
            store.clear()
        self.bounds.clear()
        if self.lineage is not None:
            self.lineage.release(self)

    # ---- evaluation ----
    def judge(self, event: TypedEvent) -> list[Hit]:
        """The behaviours this record shows (empty: none). Raises Undecided when the record cannot be judged."""
        raise NotImplementedError

    def candidate_child(self, event: TypedEvent) -> bool:
        """Could this creation be a child a parent-resolving rule judges? Only those are staged and watched on the
        pid path. A record whose image cannot be identified counts too, so the partial it causes is still counted."""
        name, _why = image_name(event.get("process.executable_key"))
        return name is None or name in SPAWNED_CODE_RUNNERS

    def consume(self, events: list[TypedEvent]) -> list[Match]:
        out: list[Match] = []
        self._batch = events
        rank = {"system_state": 0, "process_termination": 1, "process_exec": 2}
        fresh = [event for event in events if event.family in self.families and event.id not in self._seen]
        for event in sorted(fresh, key=lambda item: (item.ts, rank.get(item.family, 3),
                                                     exec_order(item)[0] if exec_order(item)[0] is not None else -1,
                                                     item.id)):
            if event.id in self._seen:             # a duplicate within one batch
                continue
            self._seen.add(event.id)
            if not self._events_pre_scoped:
                if not self.event_in_os_scope(event):
                    continue
                self.os_applicable += 1
            if self.lineage is not None:
                self.lineage.observe(event, self.raw_of(event))
            if event.family != "process_exec":
                continue
            self._judge_and_fold(event, out)
        self._batch = None
        return out

    def _checked_judge(self, event: TypedEvent) -> list[Hit]:
        if event.get("process.executable_key") in (None, ""):
            raise Undecided("image", "the process image is not recorded")
        if self.reads_command_line and event.get("process.command_line") in (None, ""):
            raise Undecided("command_line", "the command line is not recorded (Security 4688 records it only "
                                            "with command-line inclusion enabled)")
        return self.judge(event)

    def _count_undecided(self, event: TypedEvent, undecided: Undecided) -> None:
        self.missing_required += 1
        self.undecided[undecided.kind] = self.undecided.get(undecided.kind, 0) + 1
        self.note_coverage(f"undecided_{undecided.kind}",
                           f"records not judged: {undecided.text} (first seen {event.ts.isoformat()} on "
                           f"{event.host})")

    def _judge_and_fold(self, event: TypedEvent, out: list[Match]) -> None:
        """Judge a record now. On the pid path (a parent-resolving rule, no parent named in the child's own record),
        a child is staged and watched, and one whose parent a later record could still change is deferred."""
        pid_path = self.uses_parent and not _has_recorded_parent(event) and self.candidate_child(event)
        try:
            hits = self._checked_judge(event)
        except Undecided as undecided:
            if pid_path and undecided.kind in _DEFERRABLE:
                self._stage_child(event)
                self.deferred.put(event.id, 1)
                return
            self._count_undecided(event, undecided)
            return
        self.evaluated += 1
        if pid_path:
            self._stage_child(event)
        folds = [self._fold(event, hit, out) for hit in hits]
        if pid_path and hits:
            self.early.put(event.id, (_signature(hits), tuple(folds)))

    def _stage_child(self, event: TypedEvent) -> None:
        """Hand a pid-path child to the sweep's event stage (one copy per id, whichever rule hands it over) so it can
        be re-read and cited at finalize, and watch it for late records of its parent pid."""
        self._pending.append(event)
        self.lineage.watch_child(event)

    def _shape(self, event: TypedEvent, hit: Hit) -> str:
        image = image_name(event.get("process.executable_key"))[0]
        parent = hit.parent_name
        if not parent and self.uses_parent:
            parent_key = event.get("process.parent.executable_key")
            parent = (image_name(parent_key)[0] or _normalized(parent_key)) if parent_key else ""
        command = _normalized(event.get("process.command_line"))
        material = f"{self.id}|{hit.behavior}|{image}|{parent}|{command}|{hit.content}"
        return hashlib.sha256(material.encode()).hexdigest()[:32]

    def _fold(self, event: TypedEvent, hit: Hit, out: list[Match]) -> tuple[str | None, str]:
        """Publish or merge one hit. Returns (shape, "own") when the record got its own finding (shape None when it
        was published alone, outside any group) or (shape, "repeat") when it merged into the shape's fleet finding."""
        shape = self._shape(event, hit)
        member_key = (shape, event.host)
        member = self.members_store.get(member_key)
        if member is None:
            if not self.members_store.put(member_key, [1]):
                self.note_limit("fleet_members", "the per-(shape, host) membership store took no new host; this "
                                                 "record is published on its own")
                add_unheld(out, alone(self.record_match(event, hit), self, event))
                return None, "own"
            # first record of this (shape, host): published at its own lane, with its own content
            out.append(self.record_match(event, hit))
            self._note_group(shape, hit, event, new_host=True)
            return shape, "own"
        # a repeat on a host already reported for this shape: merge
        member[0] += 1
        self.members_store.put(member_key, member)
        group = self._note_group(shape, hit, event, new_host=False)
        if group is not None and not group.emitted_records:
            merged = self._fleet_match(shape, group, final=False)
            if merged is not None:
                group.emitted_records = group.records
                self.groups.put(shape, group)
                out.append(merged)
        return shape, "repeat"

    def _exclude(self, event: TypedEvent, folds: tuple) -> None:
        """Take a member whose parent a later record withdrew out of every group it was counted in: the counts, the
        hosts and the held examples (a held example stays cited as context of the final tally)."""
        for shape, _role in folds:
            if shape is None:
                continue
            member_key = (shape, event.host)
            member = self.members_store.get(member_key)
            if member is not None:
                member[0] -= 1
                self.members_store.put(member_key, member)
            group = self.groups.get(shape)
            if group is None:
                continue
            group.records -= 1
            group.excluded += 1
            if member is not None and member[0] <= 0:
                group.hosts -= 1
                if event.host in group.sample_hosts:
                    group.sample_hosts.remove(event.host)
            else:
                group.repeats -= 1
            held = len(group.examples.items)
            group.examples.items = [item for item in group.examples.items if item[0][1] != event.id]
            if len(group.examples.items) < held and len(group.withdrawn) < WITHDRAWN_CITED:
                group.withdrawn.append(event.id)
            if event.id in group.ends.ids() and event.id not in group.withdrawn_bounds:
                group.withdrawn_bounds.append(event.id)
            self.groups.put(shape, group)

    def _note_group(self, shape: str, hit: Hit, event: TypedEvent, *, new_host: bool) -> _Group | None:
        group = self.groups.get(shape)
        if group is None:
            group = _Group(hit.behavior, hit.common or hit.text, hit.lane, hit.severity, hit.attack,
                           [(p.field, p.value, p.origin) for p in hit.predicate])
            if not self.groups.put(shape, group):
                self.note_limit("fleet_groups", "the repeating-shape groups took no new shape; records of it are "
                                                "published on their own, not merged")
                return None
            self.order.put(shape, 1)
        group.records += 1
        if new_host:
            group.hosts += 1
            if len(group.sample_hosts) < FLEET_HOST_SAMPLE:
                group.sample_hosts.append(event.host)
        else:
            group.repeats += 1
        if _LANE_RANK[hit.lane] < _LANE_RANK[group.lane]:
            group.lane = hit.lane
        if _SEVERITY_RANK[hit.severity] < _SEVERITY_RANK[group.severity]:
            group.severity = hit.severity
        self.bounds.offer_at(shape, group.ends, event)
        if group.examples.offer(event):
            self._pending.append(event)
            self._fresh.append(group.examples)
        self.groups.put(shape, group)
        return group

    def record_match(self, event: TypedEvent, hit: Hit) -> Match:
        command = event.get("process.command_line")
        claim = (f"{hit.text} on {event.host} at {event.ts.isoformat()} ({event_source(event)})."
                 + (f" Recorded command line: '{clip(command)}'." if command else ""))
        notes = list(hit.notes) + [f"ATT&CK context (not proof): {', '.join(hit.attack)}"]
        context = [item for item in hit.context if item.id != event.id]
        return Match(self.id, claim, self.claim_type, [event, *context], list(hit.predicate), event.ts,
                     hit.severity, hit.lane, hit.confidence, event.entities(), notes,
                     raw_copies=dict(hit.raw_copies), context_ids={item.id for item in context})

    def _fleet_match(self, shape: str, group: _Group, *, final: bool) -> Match | None:
        """The merged finding of a repeating shape, under one identity (`<rule>|fleet|<shape>`). Published at the
        first repeat with the count so far, and revised in place to the exact tally when the sweep ends."""
        try:
            examples = group.examples.events(self.load)
            cited, missing, context = cite_group(self.load, examples, self.bounds, group.ends, named=group.withdrawn)
        except LookupError as exc:
            self.note_limit("fleet_citations", f"a repeating shape's held records were not loadable ({exc}); its "
                                               f"fleet finding is not published")
            return None
        if not cited:
            return None
        first = datetime.fromtimestamp(group.ends.first[0], UTC).isoformat() if group.ends.first else "?"
        last = datetime.fromtimestamp(group.ends.last[0], UTC).isoformat() if group.ends.last else "?"
        more = group.hosts - len(group.sample_hosts)
        host_text = ", ".join(group.sample_hosts) + (f" and {more} more host(s)" if more > 0 else "")
        lane = group.lane
        withdrawn = set(group.withdrawn) | set(group.withdrawn_bounds)
        members = [item for item in cited if item.id not in withdrawn]
        excluded = (f" {group.excluded} record(s) were excluded after later records withdrew their parent (a "
                    f"record of the parent process id inside the child's window); the interval was computed before "
                    f"that and may be wider than the remaining records'." if group.excluded else "")
        if final and group.excluded and (group.repeats <= 0 or not any(item.id not in context for item in members)):
            # no recurrence the records still support: the merged finding is lowered to a lead and says why; every
            # remaining record keeps its own finding at its own lane
            lane = "lead"
            held = ("" if any(item.id not in context for item in members)
                    else " None of the remaining records is held for citation here.")
            claim = (f"{group.common} no longer recurs as the same shape: of the records counted while the sweep "
                     f"read, {group.excluded} were excluded after later records withdrew their parent, leaving "
                     f"{max(group.records, 0)} record(s) across {max(group.hosts, 0)} host(s), each with its own "
                     f"finding.{held} The withdrawn records held for citation are cited as context.")
            reason = (f"{group.excluded} record(s) were excluded after later records withdrew their parent, so no "
                      f"recurrence remains")
        elif final:
            claim = (f"{group.common} recurred as the same shape in {group.records} process-creation record(s) "
                     f"across {group.hosts} host(s) ({group.repeats} of them repeats on a host already reported), "
                     f"{first} – {last}. Hosts: {host_text}. This finding states only what the records share; each "
                     f"host's first record keeps its own finding and remains retrievable. Sysmon and Security can "
                     f"each record the same process, so records are not processes."
                     + cited_phrase(len(members), group.records, not missing)
                     + bound_note(missing, group.ends) + excluded)
            reason = ("the final tally at the end of the sweep replaces the running count stated when the first "
                      "repeat was read")
        else:
            claim = (f"{group.common} recurred as the same shape on a host already reported for it: "
                     f"{group.records} process-creation record(s) across {group.hosts} host(s) so far (hosts so "
                     f"far: {host_text}). This running count is revised in place to the final tally when the sweep "
                     f"ends. Each host's first record keeps its own finding."
                     + cited_phrase(len(cited), group.records, not missing))
            reason = ""
        anchor = next((item for item in members if item.id not in context), members[0] if members else cited[0])
        predicate = [PredicateField(field=name, value=value, origin=origin)
                     for name, value, origin in group.predicate]
        return Match(self.id, claim, "aggregate_observation", cited, predicate, anchor.ts, group.severity,
                     lane, "high", anchor.entities(),
                     [f"ATT&CK context (not proof): {', '.join(group.attack)}",
                      ("a repeating shape is merged into one finding at the lane of its records; new hosts keep "
                       "their own findings")],
                     group_key=f"{self.id}|fleet|{shape}", context_ids=context, revision_reason=reason)

    # ---- finalize ----
    def _load_one(self, child_id: str) -> TypedEvent | None:
        found = [event for event in self.load([child_id]) if event.id == child_id]
        if not found:
            self.note_limit("parent_children", "a staged pid-path child was not loadable at finalize; its parent "
                                               "re-judgement is not done")
            return None
        return found[0]

    def _rejudge(self, event: TypedEvent) -> tuple[list[Hit], Undecided | None]:
        try:
            return self._checked_judge(event), None
        except Undecided as undecided:
            return [], undecided

    def _correction(self, event: TypedEvent, early: tuple, hits: list[Hit], undecided: Undecided | None) -> Match:
        """The corrected decision for a child whose earlier finding a late record of its parent pid changed. It has
        the earlier finding's identity (same rule, same subject record, no group key), so publishing it revises that
        candidate in place; it cites the child, the corrected parent's record when there is one, and the late
        records that changed the answer, with their raw copies."""
        count, late = self.lineage.late_records(event.id)
        late_events = [item for item, _raw in late if item.id != event.id]
        late_raw = {key: value for _item, raw in late for key, value in raw.items()}
        described = "; ".join(_late_phrase(item) for item in late_events) or "a later record of the parent pid"
        if count > len(late_events):
            described += f" (and {count - len(late_events)} more)"
        before = "; ".join(f"{behavior} at {lane} with parent '{parent or '?'}'"
                           for behavior, lane, _severity, parent in early) or "a finding"
        if hits:
            after = "; ".join(f"{hit.text} (lane {hit.lane})" for hit in hits)
            lane = min((hit.lane for hit in hits), key=lambda value: _LANE_RANK[value])
            severity = min((hit.severity for hit in hits), key=lambda value: _SEVERITY_RANK[value])
            predicate = [p for hit in hits for p in hit.predicate]
            context = [item for hit in hits for item in hit.context if item.id != event.id]
            raw = {key: value for hit in hits for key, value in hit.raw_copies.items()}
        else:
            reason = undecided.text if undecided is not None else "the parent no longer matches this rule"
            after = f"the parent attribution is withdrawn, so this is a lead: {reason}"
            lane, severity = "lead", "medium"
            predicate = [typed_field(event, "process.executable_key")]
            context, raw = [], {}
        context = list({item.id: item for item in [*context, *late_events]}.values())
        claim = (f"Revised decision for the {event_source(event)} record of {event.host} at {event.ts.isoformat()}: "
                 f"when first read, from the records then received, this rule reported {before}. Records of the "
                 f"parent process id that arrived later and fall inside the child's window ({described}) change the "
                 f"answer: {after}. The earlier version is kept in this finding's revision history.")
        revision = (f"later records of the parent pid inside the child's window ({described}) changed the parent "
                    f"decision" + ("" if hits else ": the parent is no longer resolved, so the lane is lowered to lead"))
        return Match(self.id, claim, self.claim_type, [event, *context], predicate, event.ts, severity, lane,
                     "medium", event.entities(),
                     ["revised in place after later records of the parent pid changed the earlier decision"],
                     raw_copies={**raw, **late_raw}, context_ids={item.id for item in context},
                     revision_reason=revision)

    def finalize(self) -> list[Match]:
        out: list[Match] = []
        self._batch = None
        if self.uses_parent and self.lineage is not None:
            deferred = {str(key) for key in self.deferred.keys()}  # noqa: SIM118 (a KeyedStore)
            # 1. children undecided at observation time, judged now against the complete history
            for child_id in sorted(deferred):
                event = self._load_one(child_id)
                if event is None:
                    continue
                try:
                    hits = self._checked_judge(event)
                except Undecided as undecided:
                    self._count_undecided(event, undecided)
                    continue
                self.evaluated += 1
                for hit in hits:
                    self._fold(event, hit, out)
            # 2. children judged early whose parent pid gained a record inside their window: re-judge, and publish a
            #    correction when the answer changed, or the finding when a match appears that was not there before
            #    (every pid-path child was staged when first judged, so any dirty one can be re-read here)
            for child_id in self.lineage.dirty_ids():
                if child_id in deferred:
                    continue
                event = self._load_one(child_id)
                if event is None:
                    continue
                early = self.early.peek(child_id)
                hits, undecided = self._rejudge(event)
                if early is None:
                    for hit in hits:                        # a match that a late record revealed
                        self._fold(event, hit, out)
                    continue
                signature, folds = early
                if _signature(hits) == signature:
                    continue
                # the earlier decision no longer holds: the record leaves every group it was counted in; its own
                # finding (when it had one) is revised in place, and a record that was only a merged repeat has
                # its new decision published as any record's would be
                self._exclude(event, folds)
                if any(role == "own" for _shape, role in folds):
                    out.append(self._correction(event, signature, hits, undecided))
                else:
                    if undecided is not None:
                        self._count_undecided(event, undecided)
                    for hit in hits:
                        self._fold(event, hit, out)
        # 3. every merged finding is revised in place to its exact final tally (idempotent: a re-run writes nothing);
        #    one already published is revised even when exclusions left it no repeat
        for shape in self.order.keys():  # noqa: SIM118 (a KeyedStore: first-insertion order, keys on disk too)
            group = self.groups.peek(shape)
            if group is None or (group.repeats <= 0 and not group.emitted_records):
                continue
            merged = self._fleet_match(shape, group, final=True)
            if merged is not None:
                out.append(merged)
        return out
