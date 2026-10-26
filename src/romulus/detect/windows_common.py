"""Shared machinery for Windows process-creation rules.

- Program identity comes from the OS-recorded image path (`process.executable_key`, `process.parent.executable_key`):
  its last component, compared case-insensitively. Directory prefixes (`C:\\`, `\\Device\\HarddiskVolumeN\\`,
  `\\\\?\\`), System32 versus SysWOW64 and the drive letter never matter. An image whose last component is an 8.3
  short name (`POWERS~1.EXE`) cannot be identified without guessing, so the record is not decided (it counts as
  missing a field, and the cell is partial).
- When a Security 4688 record does not carry the parent's image, `WindowsPidLineage` resolves it from the parent's own
  creation record: the latest recorded creation of the parent's process id on that host before the child, with no
  recorded termination of that id (4689, Sysmon 5) and no boot of the host in between. Records of one instant are
  ordered only inside one computer/channel record-id sequence; otherwise the parent is undecided.
- `WindowsProcessRule` publishes each match immediately, and merges a repeating shape into one fleet-level finding:
  the first `IMMEDIATE_HOSTS` hosts on which a shape (behaviour plus command line) appears are reported record by
  record as they are read, and every later record of that shape (another host, or the same host again) is counted
  into one finding for the shape, published when the sweep ends, at the lane of the shape's records. A shape that
  repeats is either a fleet-wide routine or a fleet-wide campaign; either way an analyst triages it once, with the
  host count and the bounding records cited, and nothing strong waits for the end of the hunt on a new host.
  Groups, per-host membership and process history live in disk-backed stores (`romulus.detect.bounded`); only a
  spent disk budget refuses, and then the match is published on its own and coverage says so.
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

_SHORT_NAME = re.compile(r"^[^.~\\]{1,6}~\d+(?:\.[^.\\]{0,3})?$")
_LANE_RANK = {"urgent": 0, "high": 1, "lead": 2, "context": 3}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CLAIM_TEXT_LIMIT = 300

# Programs that run code they are handed: command shells, PowerShell, script hosts and the signed binaries most used to
# proxy execution or fetch and decode payloads. Shared by the parent/child rules.
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


def _same_instant_order(a: tuple, b: tuple) -> int | None:
    """-1/0/1 for two (record id, domain) orders, None when they are not in one record-id sequence."""
    serial_a, domain_a = a
    serial_b, domain_b = b
    if serial_a is None or serial_b is None or domain_a is None or domain_a != domain_b:
        return None
    return (serial_a > serial_b) - (serial_a < serial_b)


class WindowsPidLineage:
    """Process creations and terminations per (host, pid), and boots per host, held for parent lookups. Every pid's
    history is kept (pids are reused) in a disk-backed store, so a lookup is exact however old the parent is; a store
    that refuses a new key makes later lookups on that key undecided, and coverage says so."""

    def __init__(self, owner, members: list | None = None):
        self.procs = KeyedStore(owner, "win_pid_history", HOT_COUNT)
        self.boots = KeyedStore(owner, "win_boot_history", HOT_COUNT)
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
            member.note_limit("win_pid_history", f"the process-history store took no new {what} (its share of the "
                                                 f"state budget is spent); a later parent lookup that needs it is "
                                                 f"undecided")

    def observe(self, event: TypedEvent) -> None:
        seen = (event.id, event.ts)
        if seen in self._seen:
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
            insort(boots, ts)
            return
        pid = event.get("process.pid")
        if not isinstance(pid, int) or isinstance(pid, bool):
            return
        if event.family == "process_exec":
            kind = "exec"
        elif event.family == "process_termination":
            kind = "term"
        else:
            return
        serial, domain = exec_order(event)
        entry = (ts, serial if serial is not None else -1, repr(domain), kind,
                 str(event.get("process.executable_key") or ""), event.id,
                 event.raw[0].native_id if event.raw else "", serial, domain)
        key = (event.host, pid)
        entries = self.procs.get(key)
        if entries is None:
            if not self.procs.put(key, [entry]):
                self.refused_keys.add(f"pid:{event.host}:{pid}")
                self._refused("process")
            return
        insort(entries, entry)

    def parent(self, child: TypedEvent) -> tuple[ParentImage | None, str]:
        """The parent's image from its own creation record, or (None, why it is undecided)."""
        ppid = child.get("process.ppid")
        if not isinstance(ppid, int) or isinstance(ppid, bool):
            raise Undecided("parent_pid", "the parent process id is not recorded")
        if ppid in (0, 4):
            return ParentImage("system", "system", "", "", 0.0, "pid"), ""
        key = (child.host, ppid)
        if f"pid:{child.host}:{ppid}" in self.refused_keys or (self.incomplete and key not in self.procs):
            raise Undecided("parent_refused", "the process-history store refused the parent's history")
        entries = self.procs.get(key) or []
        child_ts = child.ts.timestamp()
        child_order = exec_order(child)
        for entry in reversed(entries):
            ts, kind, image, event_id, native_id = entry[0], entry[3], entry[4], entry[5], entry[6]
            if event_id == child.id:
                continue
            if ts > child_ts:
                continue
            if ts == child_ts:
                relative = _same_instant_order((entry[7], entry[8]), child_order)
                if relative is None:
                    raise Undecided("parent_order", "the parent's record and the child's share an instant and cannot "
                                                    "be ordered outside one record-id sequence")
                if relative >= 0:
                    continue
            if kind == "term":
                raise Undecided("parent_ended", "the latest recorded process with the parent's id ended before the "
                                                "child was created, so the parent's creation is not recorded")
            boots = self.boots.get(child.host) or []
            if any(ts < boot <= child_ts for boot in boots):
                raise Undecided("parent_boot", "a boot of the host lies between the parent id's latest recorded "
                                               "creation and the child")
            name, why = image_name(image)
            if name is None:
                raise Undecided("parent_image", f"the parent's image cannot be identified: {why}")
            return ParentImage(image, name, event_id, native_id, ts, "pid"), ""
        raise Undecided("parent_unrecorded", "no creation of the parent's process id is recorded on this host before "
                                             "the child (the parent may have started before the hunt window)")


def resolve_parent(event: TypedEvent, lineage: WindowsPidLineage | None) -> ParentImage:
    """The parent image of a process-creation record: its own typed field, else the pid lineage."""
    key = event.get("process.parent.executable_key")
    if key not in (None, ""):
        name, why = image_name(key)
        if name is None:
            raise Undecided("parent_image", f"the parent's image cannot be identified: {why}")
        return ParentImage(str(key), name, event.id, "", event.ts.timestamp(), "record")
    if lineage is None:
        raise Undecided("parent_image", "the parent's image is not recorded")
    found, _why = lineage.parent(event)
    assert found is not None
    return found


# ---- the rule base ----------------------------------------------------------------------------------------------

@dataclass
class Hit:
    """One behaviour a record shows: its wording, lane and severity, and the predicate values it rests on."""
    behavior: str
    text: str
    lane: str
    severity: str
    attack: tuple[str, ...]
    predicate: list[PredicateField]
    confidence: str = "high"
    shape: str | None = None
    notes: tuple[str, ...] = ()
    context: list[TypedEvent] = field(default_factory=list)


class _Group:
    """One repeating shape: how it was first described, its records beyond the immediate ones, and what they cite."""

    __slots__ = (
        "attack",
        "behavior",
        "ends",
        "examples",
        "folded",
        "folded_hosts",
        "immediate",
        "lane",
        "predicate",
        "sample_hosts",
        "severity",
        "text",
    )

    def __init__(self, hit: Hit):
        self.behavior = hit.behavior
        self.text = clip(hit.text)
        self.lane = hit.lane
        self.severity = hit.severity
        self.attack = hit.attack
        self.immediate = 0
        self.folded = 0
        self.folded_hosts = 0
        self.examples = HeldExamples(8)
        self.ends = Ends()
        self.sample_hosts: list[str] = []
        self.predicate: list[tuple] = []

    def __getstate__(self):
        return {name: getattr(self, name) for name in self.__slots__}

    def __setstate__(self, state):
        for name, value in state.items():
            setattr(self, name, value)


def _normalized(text: object) -> str:
    return " ".join(str(text or "").casefold().split())


class WindowsProcessRule(Playbook):
    """A rule judged on one Windows process-creation record at a time (see the module notes)."""

    os_families = ("windows",)
    families: ClassVar[tuple[str, ...]] = ("process_exec",)
    kind = "aggregate"
    staged = True
    state_slice = "strong"
    claim_type = "observed_action"
    windows_event_classes = (SYSMON_PROCESS_CREATE, SECURITY_PROCESS_CREATE)
    reads_command_line: ClassVar[bool] = True
    uses_parent: ClassVar[bool] = False
    IMMEDIATE_HOSTS: ClassVar[int] = 3
    HOT = HOT_COUNT

    def __init__(self):
        super().__init__()
        self.groups = KeyedStore(self, "fleet_groups", self.HOT)
        self.shape_hosts = KeyedStore(self, "fleet_shape_hosts", self.HOT)
        self.order = SpillList(self, "fleet_order", self.HOT, refusable=False)
        self.bounds = BoundStage()
        self._pending: list[TypedEvent] = []
        self._fresh: list[HeldExamples] = []
        self._seen = RecentIds()
        self.lineage = WindowsPidLineage(self) if self.uses_parent else None
        self.undecided: dict[str, int] = {}
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
        self.shape_hosts.trim()
        self.order.trim()
        if self.lineage is not None:
            self.lineage.trim()

    def release_state(self) -> None:
        self.groups.clear()
        self.shape_hosts.clear()
        self.order.clear()
        self.bounds.clear()
        if self.lineage is not None:
            self.lineage.clear()

    # ---- evaluation ----
    def judge(self, event: TypedEvent) -> list[Hit]:
        """The behaviours this record shows (empty: none). Raises Undecided when the record cannot be judged."""
        raise NotImplementedError

    def consume(self, events: list[TypedEvent]) -> list[Match]:
        out: list[Match] = []
        self._batch = events
        rank = {"system_state": 0, "process_termination": 1, "process_exec": 2}
        fresh = [event for event in events if event.family in self.families and event.id not in self._seen]
        for event in sorted(fresh, key=lambda item: (item.ts, rank.get(item.family, 3),
                                                     exec_order(item)[0] or 0, item.id)):
            self._seen.add(event.id)
            if not self._events_pre_scoped:
                if not self.event_in_os_scope(event):
                    continue
                self.os_applicable += 1
            if self.lineage is not None:
                self.lineage.observe(event)
            if event.family != "process_exec":
                continue
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
                continue
            self.evaluated += 1
            for hit in hits:
                self._fold(event, hit, out)
        self._batch = None
        return out

    def _shape(self, event: TypedEvent, hit: Hit) -> str:
        text = hit.shape if hit.shape is not None else _normalized(event.get("process.command_line"))
        material = f"{self.id}|{hit.behavior}|{image_name(event.get('process.executable_key'))[0]}|{text}"
        return hashlib.sha256(material.encode()).hexdigest()[:32]

    def _fold(self, event: TypedEvent, hit: Hit, out: list[Match]) -> None:
        shape = self._shape(event, hit)
        host_key = (shape, event.host)
        new_host = False
        if self.shape_hosts.get(host_key) is None:
            new_host = True
            if not self.shape_hosts.put(host_key, 1):
                self.note_limit("fleet_hosts", "the per-host membership of repeating shapes took no new host; such "
                                               "records are published on their own")
                add_unheld(out, alone(self.record_match(event, hit), self, event))
                return
        group = self.groups.get(shape)
        if group is None:
            group = _Group(hit)
            if not self.groups.put(shape, group):
                self.note_limit("fleet_groups", "the repeating-shape groups took no new shape; such records are "
                                                "published on their own, not merged")
                add_unheld(out, alone(self.record_match(event, hit), self, event))
                return
            self.order.append(shape)
        if new_host and group.immediate < self.IMMEDIATE_HOSTS:
            group.immediate += 1
            out.append(self.record_match(event, hit))
            return
        group.folded += 1
        if new_host:
            group.folded_hosts += 1
            if len(group.sample_hosts) < 10:
                group.sample_hosts.append(event.host)
        if _LANE_RANK[hit.lane] < _LANE_RANK[group.lane]:
            group.lane = hit.lane
        if _SEVERITY_RANK[hit.severity] < _SEVERITY_RANK[group.severity]:
            group.severity = hit.severity
        if not group.predicate:
            group.predicate = [(p.field, p.value, p.origin) for p in hit.predicate]
        self.bounds.offer_at(shape, group.ends, event)
        if group.examples.offer(event):
            self._pending.append(event)
            self._fresh.append(group.examples)

    def record_match(self, event: TypedEvent, hit: Hit) -> Match:
        command = event.get("process.command_line")
        claim = (f"{hit.text} on {event.host} at {event.ts.isoformat()} ({event_source(event)})."
                 + (f" Recorded command line: '{clip(command)}'." if command else ""))
        notes = list(hit.notes) + [f"ATT&CK context (not proof): {', '.join(hit.attack)}"]
        context = [item for item in hit.context if item.id != event.id]
        return Match(self.id, claim, self.claim_type, [event, *context], list(hit.predicate), event.ts,
                     hit.severity, hit.lane, hit.confidence, event.entities(), notes,
                     context_ids={item.id for item in context})

    def finalize(self) -> list[Match]:
        out: list[Match] = []
        for shape in self.order:
            group = self.groups.peek(shape)
            if group is None or not group.folded:
                continue
            try:
                examples = group.examples.events(self.load)
                cited, missing, context = cite_group(self.load, examples, self.bounds, group.ends)
            except LookupError as exc:
                self.note_limit("fleet_citations", f"a repeating shape's held records were not loadable ({exc}); "
                                                   f"its fleet finding is not published")
                continue
            if not cited:
                continue
            first = datetime.fromtimestamp(group.ends.first[0], UTC).isoformat() if group.ends.first else "?"
            last = datetime.fromtimestamp(group.ends.last[0], UTC).isoformat() if group.ends.last else "?"
            hosts = ", ".join(group.sample_hosts) + (" and others" if group.folded_hosts > len(group.sample_hosts)
                                                     else "")
            claim = (f"{group.text}: the same shape recurred in {group.folded} further process-creation record(s) "
                     f"({first} – {last}), {group.folded_hosts} of them on hosts not reported before"
                     + (f" ({hosts})" if hosts else "")
                     + f", after its first {group.immediate} host(s) were reported record by record. Sysmon and "
                       f"Security can each record the same process, so records are not processes."
                     + cited_phrase(len(cited), group.folded, not missing)
                     + bound_note(missing, group.ends))
            anchor = next((item for item in cited if item.id not in context), cited[0])
            predicate = [PredicateField(field=name, value=value, origin=origin)
                         for name, value, origin in group.predicate]
            out.append(Match(self.id, claim, "aggregate_observation", cited, predicate, anchor.ts, group.severity,
                             group.lane, "high", anchor.entities(),
                             [f"ATT&CK context (not proof): {', '.join(group.attack)}",
                              "a repeating shape is merged into one finding at the lane of its records"],
                             group_key=f"{self.id}|fleet|{shape}", context_ids=context))
        return out
