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
- When a Security 4688 record does not carry the parent's image, `WindowsPidLineage` resolves it from the parent's
  own creation record: the latest recorded creation of the parent's process id on that host at or before the child,
  provided no recorded termination of that id (4689, Sysmon 5) falls after that creation and before the child, and
  no boot of the host falls between them. Records of one instant are ordered only inside one computer/channel
  record-id sequence; otherwise the parent is undecided. A fenced or unknown parent is never matched and never
  treated as a decided benign parent.
- Fleet handling (never hides a match or an attacker's payload):
  - the group key is the distinguishing content (behaviour, image, parent image for lineage rules, the normalized
    command line, and any decoded payload the rule adds), so two different payloads are never one group;
  - the first record of each (shape, host) is published immediately at its own lane, whatever the fleet size, with
    its own content;
  - only repeats on a host already reported for that shape merge, into one fleet finding per shape that lists its
    member hosts and states only what they have in common, with counts and the first and last record cited; it is
    published as soon as the first repeat exists, not only at finalize.
  Groups, per-(shape, host) membership and process history live in disk-backed stores; only a spent disk budget
  refuses, and then the record is published on its own and coverage says so.
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
from romulus.detect.bounded import HOT_COUNT, HeldExamples, KeyedStore, RecentIds, SpillList
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
    event: TypedEvent | None = None   # the parent's own creation event, for citation (pid resolution only)


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
    """One recorded process-lifecycle event of a (host, pid): a creation ("exec") or a termination ("term")."""
    ts: float
    serial: int | None
    domain: object
    kind: str                       # "exec" | "term"
    image: str = ""
    event_id: str = ""
    native_id: str = ""
    event: TypedEvent | None = None  # kept for an exec, so a lineage claim can cite the parent's creation record

    @property
    def order(self) -> tuple:
        return (self.serial, self.domain)

    def sort_key(self) -> tuple:
        return (self.ts, self.serial is None, self.serial or 0, repr(self.domain), self.kind, self.event_id)


class WindowsPidLineage:
    """One shared, time-ordered history, for every parent-resolving rule, of the creation and termination records of
    each (host, pid) and the boots of each host.

    It never forgets: entries are appended per (host, pid) in order and the whole history is kept, spilling to a
    disk-backed store when cold (only the disk budget may refuse a new key, and that refusal is stated). A parent
    lookup asks which exec of the pid was live at the child's time with no fence between, so the answer is exact
    whatever the arrival order, whichever rule asks, and whichever target (Sysmon or Security) was swept first: the
    latest-only state that lost a reused-pid parent is gone. Records of one instant are ordered only inside one
    computer/channel record-id sequence; anything else stays undecided rather than guessed."""

    def __init__(self, owner, members: list | None = None):
        self.procs: KeyedStore = KeyedStore(owner, "win_pid_history", HOT_COUNT)
        self.boots: KeyedStore = KeyedStore(owner, "win_boot_history", HOT_COUNT)
        self.members = members if members is not None else [owner]
        self._seen = RecentIds()
        self.refused_keys = RecentIds()
        self.incomplete = False

    def trim(self) -> None:
        self.procs.trim()
        self.boots.trim()

    def clear(self) -> None:
        self.procs.clear()
        self.boots.clear()

    def _refused(self, what: str) -> None:
        self.incomplete = True
        for member in self.members:
            member.note_limit("win_pid_history", f"the shared Windows process-history store took no new {what} (its "
                                                 f"share of the state budget is spent); a later parent lookup that "
                                                 f"needs it is undecided")

    def observe(self, event: TypedEvent) -> None:
        seen = (event.id, event.ts)
        if seen in self._seen:          # the same record handed over again (another rule, or a re-read/resume) is a no-op
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
            entry.event = event
        key = (event.host, pid)
        entries = self.procs.get(key)
        if entries is None:
            if not self.procs.put(key, [entry]):
                self.refused_keys.add(f"pid:{event.host}:{pid}")
                self._refused("process")
            return
        insort(entries, entry, key=_ProcEntry.sort_key)

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
        # The newest exec at or before the child is the live parent, unless a fence falls between it and the child.
        execs = [entry for entry in entries if entry.kind == "exec"]
        for exec_entry in sorted(execs, key=_ProcEntry.sort_key, reverse=True):
            rel = _before(exec_entry.order, exec_entry.ts, child_order, child_ts)
            if rel is None:
                raise Undecided("parent_order", "the parent's creation record and the child share an instant and "
                                                "cannot be ordered outside one computer/channel record-id sequence")
            if rel > 0:
                continue                                    # this exec is after the child: not the parent
            # exec_entry is the newest exec at/before the child. Is it still live at the child's time?
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
            return ParentImage(exec_entry.image, name, exec_entry.event_id, exec_entry.native_id, exec_entry.ts,
                               "pid", exec_entry.event)
        raise Undecided("parent_unrecorded", "no creation of the parent's process id is recorded at or before the "
                                             "child, so the parent's own creation is not recorded")


def parent_predicate(event: TypedEvent, parent: ParentImage) -> tuple[list[PredicateField], list[TypedEvent], str]:
    """Predicate fields for a resolved parent, the records to cite, and how the parent was resolved. When the
    parent came from the child's own Sysmon field, that field is the predicate. When it came from the parent's own
    4688 creation record (pid resolution), the parent image is carried as a predicate field whose origin points at
    that record, and the record itself is cited."""
    predicate = [typed_field(event, "process.executable_key")]
    context: list[TypedEvent] = []
    if parent.resolved_by == "record":
        predicate.append(typed_field(event, "process.parent.executable_key"))
        return predicate, context, "its own image field"
    origin = (f"{parent.native_id}:lineage:process.parent.executable_key" if parent.native_id
              else f"{parent.event_id}:lineage:process.parent.executable_key")
    predicate.append(PredicateField(field="process.parent.executable_key", value=parent.key, origin=origin))
    if parent.event is not None:
        context.append(parent.event)
    return predicate, context, "its own creation record, matched by process id"


def resolve_parent(event: TypedEvent, lineage: WindowsPidLineage | None) -> ParentImage:
    """The parent image of a process-creation record: its own typed field, else the shared pid lineage."""
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
    """Give every parent-resolving Windows rule in a pack one shared `WindowsPidLineage` (observed once, held once)."""
    holders = [pb for pb in pack if getattr(pb, "lineage", None) is not None
               and isinstance(pb.lineage, WindowsPidLineage)]
    if len(holders) < 2:
        return
    shared = WindowsPidLineage(holders[0], holders)
    for pb in holders:
        pb.lineage = shared


# ---- the rule base ----------------------------------------------------------------------------------------------

@dataclass
class Hit:
    """One behaviour a record shows: its wording, lane and severity, and the predicate values it rests on.

    `content` is the distinguishing payload used (with the command line, image and parent) to key the fleet group,
    so two different payloads are never merged. `common` is the wording a fleet finding uses for what members share.
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
    emitted: bool = False
    sample_hosts: list = field(default_factory=list)
    ends: Ends = field(default_factory=Ends)
    examples: HeldExamples = field(default_factory=lambda: HeldExamples(8))

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__.update(state)


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
        self.order: SpillList = SpillList(self, "fleet_order", self.HOT, refusable=False)
        self.bounds = BoundStage()
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self._seen = RecentIds()
        self.lineage: WindowsPidLineage | None = WindowsPidLineage(self) if self.uses_parent else None
        self.undecided: dict[str, int] = {}
        # A parent-resolving rule observes creations, terminations and boots during consume but defers judging its
        # candidate children to finalize, when the whole interval history exists. That way the answer does not
        # depend on which target (Sysmon or Security) or partition was swept first. Candidate children wait in a
        # disk-backed list (only the disk budget refuses, and that is stated).
        self._defer = self.uses_parent
        self.children: SpillList | None = SpillList(self, "parent_children", self.HOT) if self._defer else None
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

    def _trim(self) -> None:
        self.groups.trim()
        self.members_store.trim()
        self.order.trim()
        if self.children is not None:
            self.children.trim()
        if self.lineage is not None:
            self.lineage.trim()

    def release_state(self) -> None:
        self.groups.clear()
        self.members_store.clear()
        self.order.clear()
        self.bounds.clear()
        if self.children is not None:
            self.children.clear()
        if self.lineage is not None:
            self.lineage.clear()

    # ---- evaluation ----
    def judge(self, event: TypedEvent) -> list[Hit]:
        """The behaviours this record shows (empty: none). Raises Undecided when the record cannot be judged."""
        raise NotImplementedError

    def candidate_child(self, event: TypedEvent) -> bool:
        """A cheap pre-filter (parent-resolving rules only): could this creation be a child this rule judges? Only
        candidates are kept for the deferred finalize pass, so the rest of the fleet's execs are not re-judged. A
        record whose image cannot be identified is kept too, so the partial it causes is still counted honestly."""
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
            self._seen.add(event.id)
            if not self._events_pre_scoped:
                if not self.event_in_os_scope(event):
                    continue
                self.os_applicable += 1
            if self.lineage is not None:
                self.lineage.observe(event)
            if event.family != "process_exec":
                continue
            if self._defer:
                # observe now, judge at finalize (the interval history is complete only then, so the answer does
                # not depend on target/partition order). Keep only candidate children.
                if self.candidate_child(event) and not self.children.append(event):
                    self.note_limit("parent_children", "the deferred-child store took no new candidate; a later "
                                                       "parent-resolved finding may be missing")
                continue
            self._judge_and_fold(event, out)
        self._batch = None
        return out

    def _judge_and_fold(self, event: TypedEvent, out: list[Match]) -> None:
        try:
            if event.get("process.executable_key") in (None, ""):
                raise Undecided("image", "the process image is not recorded")
            if self.reads_command_line and event.get("process.command_line") in (None, ""):
                raise Undecided("command_line", "the command line is not recorded (Security 4688 records it only "
                                                "with command-line inclusion enabled)")
            hits = self.judge(event)
        except Undecided as undecided:
            self.missing_required += 1
            self.undecided[undecided.kind] = self.undecided.get(undecided.kind, 0) + 1
            self.note_coverage(f"undecided_{undecided.kind}",
                               f"records not judged: {undecided.text} (first seen {event.ts.isoformat()} on "
                               f"{event.host})")
            return
        self.evaluated += 1
        for hit in hits:
            self._fold(event, hit, out)

    def _shape(self, event: TypedEvent, hit: Hit) -> str:
        image = image_name(event.get("process.executable_key"))[0]
        parent = ""
        if self.uses_parent:
            parent_key = event.get("process.parent.executable_key")
            parent = image_name(parent_key)[0] or _normalized(parent_key) if parent_key else ""
        command = _normalized(event.get("process.command_line"))
        material = f"{self.id}|{hit.behavior}|{image}|{parent}|{command}|{hit.content}"
        return hashlib.sha256(material.encode()).hexdigest()[:32]

    def _fold(self, event: TypedEvent, hit: Hit, out: list[Match]) -> None:
        shape = self._shape(event, hit)
        member_key = (shape, event.host)
        member = self.members_store.get(member_key)
        if member is None:
            if not self.members_store.put(member_key, [1]):
                self.note_limit("fleet_members", "the per-(shape, host) membership store took no new host; this "
                                                 "record is published on its own")
                add_unheld(out, alone(self.record_match(event, hit), self, event))
                return
            # first record of this (shape, host): publish immediately at its own lane, with its own content
            out.append(self.record_match(event, hit))
            self._note_group(shape, hit, event, new_host=True)
            return
        # a repeat on a host already reported for this shape: merge
        member[0] += 1
        self.members_store.put(member_key, member)
        group = self._note_group(shape, hit, event, new_host=False)
        if group is not None and not group.emitted:
            group.emitted = True
            merged = self._fleet_match(shape, group)
            if merged is not None:
                out.append(merged)

    def _note_group(self, shape: str, hit: Hit, event: TypedEvent, *, new_host: bool) -> _Group | None:
        group = self.groups.get(shape)
        if group is None:
            group = _Group(hit.behavior, hit.common or hit.text, hit.lane, hit.severity, hit.attack,
                           [(p.field, p.value, p.origin) for p in hit.predicate])
            if not self.groups.put(shape, group):
                self.note_limit("fleet_groups", "the repeating-shape groups took no new shape; records of it are "
                                                "published on their own, not merged")
                return None
            self.order.append(shape)
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
                     context_ids={item.id for item in context})

    def _fleet_match(self, shape: str, group: _Group) -> Match | None:
        try:
            examples = group.examples.events(self.load)
            cited, missing, context = cite_group(self.load, examples, self.bounds, group.ends)
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
        claim = (f"{group.common} recurred as the same shape in {group.records} process-creation record(s) across "
                 f"{group.hosts} host(s) ({group.repeats} of them repeats on a host already reported), "
                 f"{first} – {last}. Hosts: {host_text}. This finding states only what the records share; each "
                 f"record keeps its own finding and remains retrievable. Sysmon and Security can each record the "
                 f"same process, so records are not processes."
                 + cited_phrase(len(cited), group.records, not missing)
                 + bound_note(missing, group.ends))
        anchor = next((item for item in cited if item.id not in context), cited[0])
        predicate = [PredicateField(field=name, value=value, origin=origin)
                     for name, value, origin in group.predicate]
        return Match(self.id, claim, "aggregate_observation", cited, predicate, anchor.ts, group.severity,
                     group.lane, "high", anchor.entities(),
                     [f"ATT&CK context (not proof): {', '.join(group.attack)}",
                      ("a repeating shape is merged into one finding at the lane of its records; new hosts keep "
                       "their own immediate findings")],
                     group_key=f"{self.id}|fleet|{shape}", context_ids=context)

    def finalize(self) -> list[Match]:
        out: list[Match] = []
        # Parent-resolving rules judge their deferred candidate children now, against the complete interval history,
        # so a reused-pid parent is never lost and the answer is independent of target and partition order. Each
        # child's first (shape, host) is a finding of its own; repeats merge, exactly as in the immediate path.
        if self._defer and self.children is not None:
            self._batch = None
            for event in self.children:
                self._judge_and_fold(event, out)
        for shape in self.order:
            group = self.groups.peek(shape)
            if group is None or group.repeats == 0:
                continue
            merged = self._fleet_match(shape, group)
            if merged is not None:
                out.append(merged)
        return out
