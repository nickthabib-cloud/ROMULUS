"""Per-event-family normalizers for the lab schema. Dispatch on authoritative type fields only."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise

from romulus.evidence import rpc_catalog, surrogates
from romulus.evidence.auditd import (
    AGENT_ARCH_TOKENS,
    AGENT_COPY_TYPES,
    AT_FDCWD,
    COPY_UID_EFFECTIVE_TYPES,
    O_ACCMODE,
    O_CREAT,
    O_RDWR,
    O_TMPFILE_BIT,
    O_TRUNC,
    O_WRONLY,
    SOCKET_SYSCALLS,
    AuditParseError,
    AuditRecord,
    FileCall,
    execve_argv,
    file_syscall,
    is_audit_line,
    parse_record,
    parse_sockaddr,
    record_from_agent_fields,
    socket_syscall,
    syscall_arg,
    syscall_number,
)
from romulus.evidence.certificates import certificate_fields as _certificate_fields
from romulus.evidence.certificates import dn_parts as _dn_parts
from romulus.evidence.community import community_id
from romulus.evidence.linux_auth_text import parse_auth
from romulus.evidence.linux_catalog import (
    APACHE_ACCESS,
    APACHE_ERROR,
    AUDIT_EVENT,
    AUDIT_RECORD,
    JOURNAL_FIELDS,
    JOURNAL_JSON,
    SYSLOG_LINE,
    TEXT_FAMILIES,
    WATCH_PLACEHOLDERS,
    document_dataset,
    match_shape,
    module_syscall,
    text_candidate,
    text_payload,
    unmatched_families,
)
from romulus.evidence.linux_service_text import parse_service
from romulus.evidence.linux_text import TextLine, classify, inline_time
from romulus.evidence.raw_scrub import clean_source, might_be_zeek
from romulus.evidence.typed import EVIDENCE_VERSION, FieldValue, Outcome, RawRef, TypedEvent, event_id, fv
from romulus.evidence.windows import (
    NXLOG_CHANNEL_SKIP,
    NXLOG_SHAPE,
    WindowsNotNormalized,
    is_nxlog_windows,
    is_windows_source,
    normalize_windows,
    nxlog_class_families,
    nxlog_clock_offset,
    nxlog_error_tag,
    windows_record_key,
    windows_record_signature,
)
from romulus.evidence.zeek import (
    ZEEK_DUPLICATE,
    ZEEK_INTERIM_SUPERSEDED,
    ZeekNotNormalized,
    normalize_zeek,
    plain_record,
    superseded_interim,
    zeek_record,
)
from romulus.evidence.zeek_catalog import SHAPES, lookup_log

NORMALIZER_VERSION = f"lab-ecs@{EVIDENCE_VERSION}"
RPC_REMOTE_SCOPE_SKIP = ("RPC calls withheld: local or untyped transport, or unclassified interface; "
                         "only classified remote-transport calls are evaluated")
_RPC_INTERFACES = frozenset(interface.uuid for interface in rpc_catalog.INTERFACES)
# Caveat on a process_exec event whose EXECVE arguments did not all arrive (its process.argv_complete is false).
INCOMPLETE_ARGV_CAVEAT = "command line incomplete"


class Skip(Exception):
    """Record intentionally not normalized (e.g. a duplicate copy); counted, never silent."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class TextSkip(Skip):
    """Unrecognized Linux host text can hide any text-family event."""


class AuditCopy(Skip):
    """A journald copy of an audit record: a duplicate, but its journald fields name the boot it was written in."""

    def __init__(self, record: dict, reason: str = "journal copy of an audit record (normalized from linux.audit)"):
        super().__init__(reason)
        self.record = record


def raw_digest(source: dict) -> str:
    """The digest of a record as it is stored (raw_scrub.clean_source: any record but a Zeek one, or one holding a
    lone surrogate, is stored as it is), so a copy fetched again verifies against the stored one."""
    text = json.dumps(source, sort_keys=True, separators=(",", ":"))
    if "\\ud" in text or might_be_zeek(source):
        # a non-BMP or lone surrogate escape, or a Zeek record: the stored form may differ
        text = json.dumps(clean_source(source), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s).astimezone(UTC)


def _ref(hit: dict) -> RawRef:
    return RawRef(target=hit["_index"], native_id=hit["_id"], digest=raw_digest(hit["_source"]))


def _get(src: dict, path: str):
    cur = src
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _audit_boot_field(members: list[tuple[dict, AuditRecord]]) -> dict:
    """Preserve an ECS boot identity when the shipper supplied one for an audit group."""
    for hit, _record in members:
        source = hit["_source"]
        for path in ("host.boot.id", "system.boot.id"):
            value = _get(source, path)
            if value not in (None, ""):
                return {"host.boot.id": fv(value, f"{hit['_id']}:{path}")}
    return {}


# The audit header's time of an audit event: the host's own clock when the kernel or the writing program made the
# record. It places the event in a boot; the event's own time (`ts`) may be the shipper's.
AUDIT_TIME = "audit.time"


def _audit_time(native_id: str, ts: float) -> dict:
    return {AUDIT_TIME: fv(datetime.fromtimestamp(ts, UTC).isoformat(),
                           f"{native_id}:event.original#auditd:msg.timestamp")}


# journald's boot id: 128 bits as 32 lower-case hex digits. journald sets it (an underscore field), not the writer.
_BOOT_ID = re.compile(r"[0-9a-f]{32}")


def _journal_boot(j: dict) -> str | None:
    value = j.get("_BOOT_ID")
    return value if isinstance(value, str) and _BOOT_ID.fullmatch(value) else None


# Audit record type numbers (linux/audit.h, libaudit) of the records the audit normalizers group, for journald
# copies that carry only the number (_AUDIT_TYPE) and not its name (_AUDIT_TYPE_NAME).
AUDIT_TYPE_NUMBERS = {
    "1100": "USER_AUTH", "1101": "USER_ACCT", "1102": "USER_MGMT", "1103": "CRED_ACQ", "1104": "CRED_DISP",
    "1105": "USER_START", "1106": "USER_END", "1108": "USER_CHAUTHTOK", "1110": "CRED_REFR", "1112": "USER_LOGIN",
    "1113": "USER_LOGOUT", "1114": "ADD_USER", "1115": "DEL_USER", "1116": "ADD_GROUP", "1117": "DEL_GROUP",
    "1127": "SYSTEM_BOOT", "1128": "SYSTEM_SHUTDOWN", "1129": "SYSTEM_RUNLEVEL", "1130": "SERVICE_START",
    "1131": "SERVICE_STOP", "1132": "GRP_MGMT", "1133": "GRP_CHAUTHTOK", "1135": "ACCT_LOCK", "1136": "ACCT_UNLOCK",
    "1300": "SYSCALL", "1302": "PATH", "1305": "CONFIG_CHANGE", "1306": "SOCKADDR", "1307": "CWD", "1309": "EXECVE",
    "1327": "PROCTITLE",
}


def _decimal(value) -> int | None:
    """A non-negative decimal integer written in ASCII digits, else None (str.isdigit also accepts '²')."""
    return int(value) if isinstance(value, str) and value.isascii() and value.isdigit() else None


def _audit_copy_key(hit: dict, j: dict) -> tuple[tuple[str, int, int], str, str] | None:
    """((host, audit time in ms, audit serial), audit record type, boot id) of a journald copy of an audit record,
    from journald's own fields: _AUDIT_ID is the record's serial and _SOURCE_REALTIME_TIMESTAMP its audit
    timestamp (whole milliseconds, in microseconds); the type is _AUDIT_TYPE_NAME, else the name of the number in
    _AUDIT_TYPE. None when any of them, or the shipper's host name, is missing or malformed."""
    serial, micros, boot = _decimal(j.get("_AUDIT_ID")), _decimal(j.get("_SOURCE_REALTIME_TIMESTAMP")), _journal_boot(j)
    kind = j.get("_AUDIT_TYPE_NAME")
    if not (isinstance(kind, str) and kind):
        kind = AUDIT_TYPE_NUMBERS.get(j.get("_AUDIT_TYPE")) if isinstance(j.get("_AUDIT_TYPE"), str) else None
    host = _get(hit["_source"], "host.name") or ""
    if serial is None or micros is None or micros % 1000 or not boot or not kind or not isinstance(host, str):
        return None
    return (host, micros // 1000, serial), kind, boot


def _boot_partners(copies: list[tuple[tuple[str, int, int], str, str, str]]
                   ) -> dict[tuple[str, int, int], dict[str, tuple[set[str], str]]]:
    """(host, audit ms, serial) -> {boot id: (audit record types, first journald copy id)} from journald copies
    given as (key, record type, boot id, copy id)."""
    partners: dict[tuple[str, int, int], dict[str, tuple[set[str], str]]] = defaultdict(dict)
    for key, kind, boot, copy_id in copies:
        types, first = partners[key].get(boot, (set(), copy_id))
        types.add(kind)
        partners[key][boot] = (types, min(first, copy_id))
    return partners


def _partner_boot(partners: dict, host: str, ts: float, serial: int,
                  members: list[tuple[dict, AuditRecord]]) -> dict:
    """The boot id of an audit event from journald's copy of one of its records, joined on (host, audit timestamp,
    serial) and a matching record type. No copy in the batch, or copies naming two boots, leaves it unknown."""
    types = {record.type for _hit, record in members}
    boots = [(boot, first) for boot, (kinds, first) in partners.get((host, round(ts * 1000), serial), {}).items()
             if kinds & types]
    if len(boots) != 1:
        return {}
    boot, first = boots[0]
    return {"host.boot.id": fv(boot, f"{first}:event.original#journal:_BOOT_ID")}


# ---------------------------------------------------------------------------------------------
# Boot intervals: when each boot of a host was observed running
# ---------------------------------------------------------------------------------------------

# Families an audit group yields. Their records name no boot of their own; the boot-interval map may supply it.
BOOT_FILL_FAMILIES = frozenset({"process_exec", "net_socket", "file_change", "file_access", "kernel_module", "auth", "account_change",
                                "service_change", "audit_config", "system_state", "process_observed"})
# How far inside one boot's observed span, and away from every other boot's span and every boot record that names
# no boot, an event's time must lie before the event is placed in that boot. Every time compared is the host's own
# clock (the audit header, journald's receive or source time), so the margin covers only the difference between
# when a program made a record and when journald received it, which is about a second. A larger clock step at a
# reboot puts records of two boots at overlapping times, and a time inside two spans is never placed.
BOOT_EDGE_SKEW = timedelta(seconds=30)
# The origin suffix of a boot id this map placed: an inference of one hunt, never a record's statement.
BOOT_INTERVAL_ORIGIN = "#derived:boot-interval"
# Why an event without a boot id was not placed.
UNPLACED_NO_CLOCK = "no host-clock time"
UNPLACED_NO_BOOT = "no boot observed on this host"
UNPLACED_OVERLAP = "overlapping boots"
UNPLACED_BOUNDARY = "near a boot record that names no boot"
UNPLACED_EDGE = "between boots or near a boot's first or last record"
UNPLACED_STOPPED = "sweep placement stopped on this host"
_US = timedelta(microseconds=1)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _micros(when: datetime) -> int:
    """Whole microseconds since the epoch (a naive time is UTC, as the store defines it)."""
    return ((when.replace(tzinfo=UTC) if when.tzinfo is None else when) - _EPOCH) // _US


def _iso(micros: int) -> str:
    return (_EPOCH + micros * _US).isoformat()


def host_clock_us(event: TypedEvent) -> int | None:
    """The time the event's host gave it by its own clock (the audit header), in µs; None when the event carries
    none. The shipper's timestamp is never used: a shipper that stamps send or receive time can stamp an old boot's
    record after a reboot."""
    value = event.get(AUDIT_TIME)
    if not isinstance(value, str):
        return None
    try:
        return _micros(datetime.fromisoformat(value))
    except ValueError:
        return None


def _without_zones(pieces: list[tuple[int, int, str]], centres: list[int], radius: int) -> list[tuple[int, int, str]]:
    """Sorted disjoint closed ranges (first, last, boot) with every time within `radius` of a sorted centre
    removed. Each range looks only at the centres that reach it."""
    out: list[tuple[int, int, str]] = []
    for lo, hi, boot in pieces:
        i, cur = bisect_left(centres, lo - radius), lo
        while i < len(centres) and centres[i] - radius <= hi:
            if centres[i] - radius > cur:
                out.append((cur, centres[i] - radius - 1, boot))
            cur = max(cur, centres[i] + radius + 1)
            i += 1
        if cur <= hi:
            out.append((cur, hi, boot))
    return out


def _merge_zones(zones: list[tuple[int, int, frozenset[str]]]) -> list[tuple[int, int, frozenset[str]]]:
    """Closed ranges (first, last, boots) sorted by first, with ranges that meet or touch merged."""
    out: list[tuple[int, int, frozenset[str]]] = []
    for lo, hi, boots in zones:
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi), out[-1][2] | boots)
        else:
            out.append((lo, hi, boots))
    return out


@dataclass
class _HostIndex:
    """One host's placeable times as sorted disjoint closed ranges (first µs, last µs, boot) with their first
    times for bisection; the overlaps of two or more boots' spans widened by the skew (first µs, last µs, boots),
    sorted and merged; and the host's boundary times, sorted."""
    starts: list[int]
    segments: list[tuple[int, int, str]]
    overlap_starts: list[int]
    overlaps: list[tuple[int, int, frozenset[str]]]
    boundaries: list[int]


@dataclass
class _Span:
    """One boot's observations on one host: the earliest and latest as (time in µs, record id), their count, and
    the earliest typed boot record (kernel boot banner or SYSTEM_BOOT) that names this boot."""
    first: tuple[int, str]
    last: tuple[int, str]
    observations: int = 0
    marker: tuple[int, str] | None = None


class BootIntervals:
    """Per host, the span of time each boot was observed running, built from typed records that name a boot with
    a time by the host's own clock: every journald record (`_BOOT_ID`, at each host-clock time it states, see
    `_journal_observations`) and every audit event whose boot came from the shipper or from a journald copy (at its
    audit header time). Typed boot records (the kernel's boot banner, SYSTEM_BOOT) that name a boot count as
    observations of it; one that names no boot (SYSTEM_BOOT or SYSTEM_SHUTDOWN) is a boundary. A record that names a
    boot or bounds one without a host-clock time is counted per host, never placed in time by its shipper's stamp.

    A boot id belongs to one boot, and a host runs one boot at a time, so a time well inside one boot's span belongs
    to that boot. An event without a boot id is placed only by its own host-clock time, and only when that is at
    least BOOT_EDGE_SKEW inside exactly one span of its host, and at least that far from every other span and every
    boundary. Where two boots' spans overlap (a clock step at a reboot, or two machines under one host name),
    nothing places in the overlap widened by the skew; each boot still places outside it, and the overlap is
    listed per host (`blind`). A time in a gap between boots, near an edge, inside an overlap, on a host with no
    span, or an event without a host-clock time stays unknown: never guessed, and two recorded boots never merge.

    The sweep builds the map batch by batch and places each batch's events with what it has read so far
    (`fill(..., incremental=True)`). A record read later can still refuse a time placed earlier: a boot record
    naming no boot, or another boot's record at the same host-clock time, shipped late. Each incremental placement
    is remembered per placeable range; when the map changes so that a remembered range no longer places in its boot,
    the range is recorded as a sweep conflict and the sweep places nothing more on that host. Expansion and the
    context pass use the whole map."""

    def __init__(self, skew: timedelta = BOOT_EDGE_SKEW):
        self.skew_us = skew // _US
        self.spans: dict[str, dict[str, _Span]] = {}
        self.boundaries: dict[str, set[tuple[int, str]]] = {}
        # Per host: records that named a boot or bounded one but carried no host-clock time.
        self.unclocked: dict[str, int] = {}
        # Incremental (sweep) placement: per host, why events were not placed; the placed times as
        # {first µs of the placeable range they fell in: (boot, earliest, latest)}; ranges a later map refused.
        self.unplaced: dict[str, Counter[str]] = {}
        self._placed: dict[str, dict[int, tuple[str, int, int]]] = {}
        self.conflicts: dict[str, list[tuple[str, int, int]]] = {}
        # Per host, until it is observed again: its placement index.
        self._segments: dict[str, _HostIndex] = {}

    def __bool__(self) -> bool:
        return bool(self.spans)

    def observe(self, host: str, boot: str, when_us: int, ref: str, marker: bool = False) -> None:
        self._segments.pop(host, None)
        point = (when_us, ref)
        span = self.spans.setdefault(host, {}).get(boot)
        if span is None:
            span = self.spans[host][boot] = _Span(first=point, last=point)
        span.first, span.last = min(span.first, point), max(span.last, point)
        span.observations += 1
        if marker:
            span.marker = point if span.marker is None else min(span.marker, point)

    def boundary(self, host: str, when_us: int, ref: str) -> None:
        self._segments.pop(host, None)
        self.boundaries.setdefault(host, set()).add((when_us, ref))

    def observe_unclocked(self, host: str) -> None:
        self.unclocked[host] = self.unclocked.get(host, 0) + 1

    def observe_event(self, event: TypedEvent) -> None:
        """An audit event's own boot id (shipper or journald copy) is an observation at its audit header time; a
        boot or shutdown record without one is a boundary there. Boot ids this map derived are never
        observations."""
        if not event.host or not event.raw:
            return
        state = event.get("system.event") if event.family == "system_state" else None
        boot = event.fields.get("host.boot.id")
        recorded = boot is not None and boot.value not in (None, "") and not boot.origin.endswith(BOOT_INTERVAL_ORIGIN)
        if not recorded and state not in ("boot", "shutdown"):
            return
        when = host_clock_us(event)
        if when is None:
            self.observe_unclocked(event.host)
        elif recorded:
            self.observe(event.host, str(boot.value), when, event.raw[0].native_id, state == "boot")
        else:
            self.boundary(event.host, when, event.raw[0].native_id)

    def _index(self, host: str) -> _HostIndex:
        """The host's placement index, built once per change to the host's observations in
        O((boots + boundaries) log), so that placing an event is one bisection however many boots and boundaries
        the host has. A time places in boot b when it is at least the skew inside b's span and more than the skew
        from every other boot's span and every boundary: so two boots' spans that overlap refuse only their overlap
        widened by the skew, and each boot still places outside it. Rebuilding checks the sweep's earlier
        placements on the host against the new ranges."""
        cached = self._segments.get(host)
        if cached is not None:
            return cached
        skew, spans = self.skew_us, self.spans.get(host, {})
        # Sweep the spans widened by the skew: a stretch covered by exactly one boot's widened span may place in
        # that boot, inside its span shrunk by the skew. A stretch where two or more boots' own spans meet is an
        # overlap.
        points: dict[int, list[tuple[int, str]]] = defaultdict(list)
        for boot, span in spans.items():
            points[span.first[0] - skew].append((1, boot))
            points[span.last[0] + skew + 1].append((-1, boot))
            points[span.first[0]].append((2, boot))
            points[span.last[0] + 1].append((-2, boot))
        near: set[str] = set()
        inside: set[str] = set()
        pieces: list[tuple[int, int, str]] = []
        zones: list[tuple[int, int, frozenset[str]]] = []
        xs = sorted(points)
        for x, nxt in pairwise(xs):
            for change, boot in points[x]:
                group = near if abs(change) == 1 else inside
                (group.add if change > 0 else group.discard)(boot)
            if len(near) == 1:
                boot = next(iter(near))
                lo, hi = max(x, spans[boot].first[0] + skew), min(nxt - 1, spans[boot].last[0] - skew)
                if lo <= hi:
                    if pieces and pieces[-1][2] == boot and pieces[-1][1] + 1 == lo:
                        pieces[-1] = (pieces[-1][0], hi, boot)
                    else:
                        pieces.append((lo, hi, boot))
            if len(inside) > 1:
                zones.append((x - skew, nxt - 1 + skew, frozenset(inside)))
        centres = sorted({at for at, _ref in self.boundaries.get(host, ())})
        segments = _without_zones(pieces, centres, skew)
        overlaps = _merge_zones(zones)
        index = self._segments[host] = _HostIndex([lo for lo, _hi, _boot in segments], segments,
                                                  [lo for lo, _hi, _boots in overlaps], overlaps, centres)
        self._recheck(host, index)
        return index

    def _recheck(self, host: str, index: _HostIndex) -> None:
        """Each range of earlier incremental placements on the host must still lie in one placeable range of its
        boot. One that does not is a sweep conflict: the whole map would not have placed some of it there."""
        placed = self._placed.get(host)
        if not placed:
            return
        kept: dict[int, tuple[str, int, int]] = {}
        for boot, lo, hi in placed.values():
            i = bisect_right(index.starts, lo) - 1
            if i >= 0 and index.segments[i][2] == boot and hi <= index.segments[i][1]:
                old = kept.get(index.starts[i])
                kept[index.starts[i]] = (boot, lo, hi) if old is None else (boot, min(old[1], lo), max(old[2], hi))
            else:
                self.conflicts.setdefault(host, []).append((boot, lo, hi))
        self._placed[host] = kept

    def _segment_at(self, host: str, when_us: int) -> tuple[int, str] | None:
        """(first µs of the placeable range, boot) the host's time falls in, or None."""
        index = self._index(host)
        i = bisect_right(index.starts, when_us) - 1
        if i < 0 or when_us > index.segments[i][1]:
            return None
        return index.starts[i], index.segments[i][2]

    def why_not(self, host: str, when_us: int) -> str:
        """Why the host's time places in no boot (for a time that does not)."""
        index = self._index(host)
        if not self.spans.get(host):
            return UNPLACED_NO_BOOT
        i = bisect_right(index.overlap_starts, when_us) - 1
        if i >= 0 and when_us <= index.overlaps[i][1]:
            return UNPLACED_OVERLAP
        j = bisect_left(index.boundaries, when_us - self.skew_us)
        if j < len(index.boundaries) and index.boundaries[j] <= when_us + self.skew_us:
            return UNPLACED_BOUNDARY
        return UNPLACED_EDGE

    def blind(self, host: str) -> list[dict]:
        """The host's ranges inside boot spans where nothing places because two or more boots overlap there
        (a clock step at a reboot, or two machines under one host name), widened by the skew."""
        return [{"from": _iso(lo), "to": _iso(hi), "reason": UNPLACED_OVERLAP, "boots": sorted(boots)}
                for lo, hi, boots in self._index(host).overlaps]

    def boot_at(self, host: str, when_us: int) -> tuple[str, _Span] | None:
        """The one boot this host's time falls in, with its span, or None (see the class)."""
        found = self._segment_at(host, when_us)
        return None if found is None else (found[1], self.spans[host][found[1]])

    def settle(self) -> None:
        """Check every host's earlier incremental placements against the map as it now stands."""
        for host in list(self._placed):
            self._index(host)

    def fill(self, events: list[TypedEvent], *, rederive: bool = False, incremental: bool = False) -> Counter[str]:
        """Give each host-record event without a boot id the boot its host-clock time falls in, citing the span's
        first and last records, and return why the others were not placed. With `rederive`, a boot id an earlier,
        smaller map (or another hunt's map: stored rows are shared) derived is placed again by this one, and
        removed when this one cannot place it; an empty map removes it. A boot id a record states is never
        changed. With `incremental` (the sweep, part way through its reading), placements are remembered for
        checking against later records, and nothing is placed on a host where such a check has failed."""
        reasons: Counter[str] = Counter()
        if not self.spans and not incremental and not rederive:
            return reasons
        for event in events:
            if event.family not in BOOT_FILL_FAMILIES or not event.host:
                continue
            current = event.fields.get("host.boot.id")
            derived = current is not None and current.origin.endswith(BOOT_INTERVAL_ORIGIN)
            if current is not None and current.value not in (None, "") and not (rederive and derived):
                continue
            when, found = host_clock_us(event), None
            if incremental:
                self._index(event.host)          # current, so the host's earlier placements have been rechecked
            if when is None:
                reason = UNPLACED_NO_CLOCK
            elif incremental and event.host in self.conflicts:
                reason = UNPLACED_STOPPED
            else:
                found = self._segment_at(event.host, when)
                reason = None if found is not None else self.why_not(event.host, when)
            if found is None:
                reasons[reason] += 1
                if incremental:
                    self.unplaced.setdefault(event.host, Counter())[reason] += 1
                if derived:
                    del event.fields["host.boot.id"]
                continue
            start, boot = found
            span = self.spans[event.host][boot]
            event.fields["host.boot.id"] = fv(boot, f"{span.first[1]}..{span.last[1]}{BOOT_INTERVAL_ORIGIN}")
            if incremental:
                placed = self._placed.setdefault(event.host, {})
                old = placed.get(start)
                placed[start] = (boot, when, when) if old is None else (boot, min(old[1], when), max(old[2], when))
        return reasons

    def conflict_list(self) -> list[dict]:
        """Every sweep conflict as {host, boot, from, to}, in host and time order."""
        return [{"host": host, "boot": boot, "from": _iso(lo), "to": _iso(hi)}
                for host in sorted(self.conflicts) for boot, lo, hi in sorted(self.conflicts[host], key=lambda c: c[1:])]

    def to_json(self) -> dict:
        self.settle()

        def span_json(boot: str, span: _Span) -> dict:
            return {"boot": boot, "first": _iso(span.first[0]), "first_ref": span.first[1],
                    "last": _iso(span.last[0]), "last_ref": span.last[1], "observations": span.observations,
                    "marker": None if span.marker is None else _iso(span.marker[0]),
                    "marker_ref": None if span.marker is None else span.marker[1]}
        hosts = {}
        for host in sorted(set(self.spans) | set(self.boundaries) | set(self.unclocked) | set(self.conflicts)):
            spans = sorted(self.spans.get(host, {}).items(), key=lambda item: (item[1].first, item[0]))
            entry = hosts[host] = {"boots": [span_json(boot, span) for boot, span in spans],
                                   "boundaries": [{"at": _iso(at), "ref": ref}
                                                  for at, ref in sorted(self.boundaries.get(host, ()))]}
            blind = self.blind(host)
            if blind:
                entry["blind"] = blind
            if self.unclocked.get(host):
                entry["unclocked_records"] = self.unclocked[host]
            if self.conflicts.get(host):
                entry["sweep_conflicts"] = [{"boot": boot, "from": _iso(lo), "to": _iso(hi)}
                                            for boot, lo, hi in sorted(self.conflicts[host], key=lambda c: c[1:])]
        return {"skew_seconds": self.skew_us / 1_000_000, "hosts": hosts}

    @classmethod
    def from_json(cls, data: dict) -> BootIntervals:
        out = cls(timedelta(seconds=data["skew_seconds"])) if "skew_seconds" in data else cls()
        for host, entry in (data.get("hosts") or {}).items():
            for item in entry.get("boots", []):
                marker = item.get("marker")
                out.spans.setdefault(host, {})[item["boot"]] = _Span(
                    first=(_micros(datetime.fromisoformat(item["first"])), item["first_ref"]),
                    last=(_micros(datetime.fromisoformat(item["last"])), item["last_ref"]),
                    observations=int(item.get("observations", 0)),
                    marker=None if marker is None else (_micros(datetime.fromisoformat(marker)), item["marker_ref"]))
            for item in entry.get("boundaries", []):
                out.boundary(host, _micros(datetime.fromisoformat(item["at"])), item["ref"])
            if entry.get("unclocked_records"):
                out.unclocked[host] = int(entry["unclocked_records"])
            for item in entry.get("sweep_conflicts", []):
                out.conflicts.setdefault(host, []).append((item["boot"], _micros(datetime.fromisoformat(item["from"])),
                                                           _micros(datetime.fromisoformat(item["to"]))))
        return out


def _journal_observations(hit: dict, j: dict) -> list[tuple[str, str, int | None, str, bool]]:
    """(host, boot id, time in µs, record id, kernel boot banner) for each distinct host-clock time a journald
    record states: journald's receive time (`__REALTIME_TIMESTAMP`) and the time the record was made
    (`_SOURCE_REALTIME_TIMESTAMP`; for a copy of an audit record, its audit time). Both are journald's own fields on
    the host's clock. The shipper's timestamp is never used: a shipper that stamps when it sent a record late,
    after a reboot, would widen the old boot's span over the new one's. A record with neither time is one entry
    with time None (counted, never placed in time). The host is the shipper's, as for audit records. Empty without
    a well-formed boot id and host."""
    src = hit["_source"]
    boot, host = _journal_boot(j), _get(src, "host.name")
    if not boot or not isinstance(host, str) or not host:
        return []
    times = {_decimal(j.get("__REALTIME_TIMESTAMP")), _decimal(j.get("_SOURCE_REALTIME_TIMESTAMP"))} - {None}
    # The kernel's boot banner on the kernel transport. User space cannot write kernel-facility (0) messages.
    message = j.get("MESSAGE")
    banner = (j.get("_TRANSPORT") == "kernel" and str(j.get("SYSLOG_FACILITY")) == "0"
              and isinstance(message, str) and message.startswith("Linux version "))
    return [(host, boot, when, hit["_id"], banner) for when in (sorted(times) or [None])]


# ---------------------------------------------------------------------------------------------
# linux.audit: multi-record events grouped by (host, serial)
# ---------------------------------------------------------------------------------------------

EXEC_COMPANIONS = {"EXECVE", "SYSCALL", "CWD", "PROCTITLE"}


def group_audit(hits: list[dict], parse: Callable[[dict, str], AuditRecord] | None = None,
                ) -> tuple[dict[tuple[str, float, int], list[tuple[dict, AuditRecord]]], list[tuple[str, str]]]:
    """Group audit records into events by (host, audit timestamp, serial). Records that cannot be
    parsed, or lack the authoritative raw text, are returned as errors: they are never dropped
    silently, because a dropped exec record would make a negative look complete. `parse(hit, raw)` parses one
    record's raw text (a caller that already parsed the batch passes its parses); it raises AuditParseError."""
    groups: dict[tuple[str, float, int], list[tuple[dict, AuditRecord]]] = defaultdict(list)
    errors: list[tuple[str, str]] = []
    for h in hits:
        src = h["_source"]
        raw = _get(src, "event.original") or src.get("message")
        if document_dataset(src) != "linux.audit" and not is_audit_line(raw):
            # a shipper that indexed the fields it parsed and not the raw line: rebuild the record from them
            try:
                rec = record_from_agent_fields(src)
            except AuditParseError as e:
                errors.append((h["_id"], f"linux.audit: record cannot be rebuilt from the shipper's fields: {e}"))
                continue
            groups[(audit_host(src, rec), rec.ts, rec.serial)].append((h, rec))
            continue
        if not raw:
            errors.append((h["_id"], "linux.audit: missing authoritative event.original/message"))
            continue
        try:
            rec = parse_record(raw) if parse is None else parse(h, raw)
        except AuditParseError as e:
            errors.append((h["_id"], f"linux.audit: unparseable record: {e}"))
            continue
        groups[(audit_host(src, rec), rec.ts, rec.serial)].append((h, rec))
    return groups, errors


def audit_host(source: dict, record: AuditRecord) -> str:
    """The host an audit record is indexed under: the shipper's host.name, which host pivots, the exec-holder lookup
    and the journald pairing search by. Only a document without one (forwarded or aggregated) falls back to the
    record's own node= name (the empty string when neither is recorded)."""
    indexed = _get(source, "host.name")
    if isinstance(indexed, str) and indexed:
        return indexed
    node = audit_node(source, record)
    return node or ""


def audit_node(source: dict, record: AuditRecord) -> str | None:
    """The node= name an audit record states (its header's, else the one the shipper parsed), else None."""
    node = record.node or _get(source, "auditd.log.node")
    return node if isinstance(node, str) and node else None


HOST_FALLBACK_CAVEAT = ("Host from the record's own host name: the document names no host.name, so host searches "
                        "by host.name do not find it")


def _audit_node_fields(event: TypedEvent, members: list[tuple[dict, AuditRecord]]) -> None:
    """Name the node= host an event's records state (host.node), and say when it stands in for a missing host.name."""
    cited = {ref.native_id for ref in event.raw}
    for hit, record in members:
        if hit["_id"] not in cited:
            continue
        node = audit_node(hit["_source"], record)
        if node:
            origin = (f"{hit['_id']}:auditd.log.node" if record.node is None
                      else f"{hit['_id']}:event.original#auditd:node")
            event.fields["host.node"] = fv(node, origin)
            indexed = _get(hit["_source"], "host.name")
            if not (isinstance(indexed, str) and indexed) and HOST_FALLBACK_CAVEAT not in event.caveats:
                event.caveats.append(HOST_FALLBACK_CAVEAT)
            return


def _indexed_host(event: TypedEvent, hit: dict) -> TypedEvent:
    """A journald or syslog event's host: the shipper's host.name, with the record's own host name (host.hostname)
    as a typed field; that name is the host only when the document names no host.name."""
    src = hit["_source"]
    native, indexed = _get(src, "host.hostname"), _get(src, "host.name")
    if isinstance(native, str) and native:
        event.fields["host.hostname"] = fv(native, f"{hit['_id']}:host.hostname")
    if isinstance(indexed, str) and indexed:
        event.host = indexed
    elif isinstance(native, str) and native:
        event.host = native
        if HOST_FALLBACK_CAVEAT not in event.caveats:
            event.caveats.append(HOST_FALLBACK_CAVEAT)
    return event


def audit_record_of(hit: dict, parse: Callable[[dict, str], AuditRecord] | None = None) -> AuditRecord | None:
    """The one audit record a hit of a record shape holds (a raw line, or a shipper's parsed fields), else None
    (not such a hit). Raises AuditParseError when it is one but cannot be read."""
    source = hit.get("_source") or {}
    found = match_shape(source)
    if found is None or found[1].shape != AUDIT_RECORD:
        return None
    raw = _get(source, "event.original") or source.get("message")
    if document_dataset(source) != "linux.audit" and not is_audit_line(raw):
        return record_from_agent_fields(source)
    if not raw:
        raise AuditParseError("missing authoritative event.original/message")
    return parse_record(raw) if parse is None else parse(hit, raw)


def merge_execve(execs: list[tuple[dict, AuditRecord]]) -> tuple[dict, AuditRecord]:
    """auditd splits an exec with a very long argv across several EXECVE records: the first carries
    argc, continuations carry later aN fields. Merge them. Two records both carrying argc, or the same
    argument field with different values, are ambiguous and raise (never silently pick one). When the record
    carrying argc was lost the continuations are still merged; execve_argv reports the command line incomplete."""
    if len(execs) == 1:
        return execs[0]
    if any(r.reconstructed for _h, r in execs):
        # a shipper that parsed the records lost each split argument's chunk numbers: never splice them
        h_head, r_head = next(((h, r) for h, r in execs if "argc" in r.raw_fields), execs[0])
        problem = (f"the command line spans {len(execs)} EXECVE records and the shipper kept no chunk numbers of "
                   "split arguments")
        return h_head, AuditRecord(type="EXECVE", ts=r_head.ts, serial=r_head.serial, fields=r_head.fields,
                                   raw_fields=r_head.raw_fields, enriched=r_head.enriched, node=r_head.node,
                                   origins=r_head.origins or {},
                                   argv_problem="; ".join(p for p in (r_head.argv_problem, problem) if p),
                                   hex_guessed=r_head.hex_guessed)
    heads = [(h, r) for h, r in execs if "argc" in r.raw_fields]
    if len(heads) > 1:
        raise AuditParseError(f"ambiguous exec event: {len(heads)} EXECVE records carry argc")
    h_head, r_head = heads[0] if heads else execs[0]
    raw, fields = dict(r_head.raw_fields), dict(r_head.fields)
    for _h, r in execs:
        if r is r_head:
            continue
        for k, v in r.raw_fields.items():
            if k in raw and raw[k] != v:
                raise AuditParseError(f"conflicting EXECVE continuation for {k}")
            raw[k] = v
            fields[k] = r.fields[k]
    merged = AuditRecord(type="EXECVE", ts=r_head.ts, serial=r_head.serial, fields=fields, raw_fields=raw,
                         enriched=r_head.enriched)
    return h_head, merged


def _syscall_process_fields(sid: str, rs: AuditRecord) -> dict:
    """Process identity from a SYSCALL record, with field lineage. Absent fields stay absent."""
    f = {}
    for name, key in (("process.pid", "pid"), ("process.ppid", "ppid")):
        if rs.fields.get(key, "").isdigit():
            f[name] = fv(int(rs.fields[key]), f"{sid}:event.original#auditd:SYSCALL.{key}")
    if rs.fields.get("exe"):
        f["process.executable"] = fv(rs.fields["exe"], f"{sid}:event.original#auditd:SYSCALL.exe")
    if rs.fields.get("comm"):
        f["process.comm"] = fv(rs.fields["comm"], f"{sid}:event.original#auditd:SYSCALL.comm")
    for name, key in (("process.uid", "uid"), ("process.euid", "euid"), ("process.auid", "auid")):
        if key in rs.fields and not (key == "auid" and rs.fields[key] in {"-1", "4294967295"}):
            f[name] = fv(rs.fields[key], f"{sid}:event.original#auditd:SYSCALL.{key}")
    session_id = rs.fields.get("ses")
    if session_id and session_id.isdigit() and session_id != "4294967295":
        f["process.session_id"] = fv(
            int(session_id), f"{sid}:event.original#auditd:SYSCALL.ses",
        )
    for name, key in (("process.user", "UID"), ("process.effective_user", "EUID"),
                      ("process.login_user", "AUID")):
        if key in rs.enriched:
            f[name] = fv(rs.enriched[key], f"{sid}:event.original#auditd:enriched.{key}")
    if rs.fields.get("tty"):
        f["process.tty"] = fv(rs.fields["tty"], f"{sid}:event.original#auditd:SYSCALL.tty")
    return f


SOCKET_COMPANIONS = {"SYSCALL", "SOCKADDR", "PROCTITLE"}
EINPROGRESS = "-115"
AUDIT_LOGIN_TYPES = {"USER_LOGIN", "USER_START"}
# What an auth record is: an authentication decision, a completed login, or a (PAM) session opening. One login
# can appear as all three (journal sshd "Accepted", audit USER_LOGIN, audit USER_START); rules count logins.
AUTH_PHASE = {"USER_LOGIN": "login", "USER_START": "session_open"}


def normalize_audit_auth_group(host: str, members: list[tuple[dict, AuditRecord]]) -> TypedEvent:
    """Normalize authoritative audit login/session records into the shared auth family."""
    login_members = sorted(
        ((hit, record) for hit, record in members if record.type in AUDIT_LOGIN_TYPES),
        key=lambda item: (item[1].type != "USER_LOGIN", item[0]["_id"]),
    )
    hit, record = login_members[0]
    native_id = hit["_id"]
    refs = [_ref(item_hit) for item_hit, item_record in login_members]
    origin = f"{native_id}:event.original#auditd:{record.type}"
    fields = {
        "auth.method": fv(record.type.lower(), f"{origin}.type"),
        "auth.phase": fv(AUTH_PHASE[record.type], f"{origin}.type"),
        **_audit_boot_field(members), **_audit_time(native_id, record.ts),
    }
    executable = record.fields.get("exe")
    if executable:
        service = executable.rsplit("/", 1)[-1]
        fields["auth.service"] = fv(service, f"{origin}.exe")
    session_id = record.fields.get("ses")
    if session_id and session_id.isdigit() and session_id != "4294967295":
        fields["process.session_id"] = fv(int(session_id), f"{origin}.ses")
    auid = record.fields.get("auid")
    if auid not in {None, "", "-1", "4294967295"}:
        fields["process.auid"] = fv(auid, f"{origin}.auid")
    # The login account is `acct`, else the audit (login) uid's name. Never UID: that is the process writing the
    # record (sshd), so a failed login by an unknown user would read as root.
    placeholders = {None, "", "?", "(null)", "(none)", "unset", "(unknown)"}
    if record.fields.get("acct") not in placeholders:
        fields["user.name"] = fv(record.fields["acct"], f"{origin}.acct")
    elif record.enriched.get("AUID") not in placeholders:
        fields["user.name"] = fv(record.enriched["AUID"], f"{origin}.AUID")
    address = record.fields.get("addr")
    if address not in {None, "", "?", "(null)", "(none)", "0.0.0.0", "::"}:
        fields["source.ip"] = fv(address, f"{origin}.addr")
    pid = record.fields.get("pid")
    if pid and pid.isdigit():
        fields["process.pid"] = fv(int(pid), f"{origin}.pid")
    result = (record.fields.get("res") or "").strip("'\"").lower()
    outcome = (Outcome.success if result in {"success", "yes"}
               else Outcome.failure if result in {"failed", "failure", "no"}
               else Outcome.unknown)
    return TypedEvent(
        id=event_id("auth", refs), family="auth", ts=datetime.fromtimestamp(record.ts, UTC),
        host=host or None, outcome=outcome, fields=fields, raw=refs,
        normalizer=NORMALIZER_VERSION,
    )


# Account and group management records that shadow-utils, PAM and the adduser family write through libaudit. The
# record type is the action the tool reports; `op` (when it is one clean token) is the tool's own detail.
AUDIT_ACCOUNT_TYPES = {"ADD_USER": "create_user", "DEL_USER": "delete_user", "ADD_GROUP": "create_group",
                       "DEL_GROUP": "delete_group", "USER_MGMT": "modify_user", "GRP_MGMT": "modify_group",
                       "USER_CHAUTHTOK": "password_change", "GRP_CHAUTHTOK": "group_password_change",
                       "ACCT_LOCK": "lock", "ACCT_UNLOCK": "unlock"}
# The service manager's unit records, and the system state records systemd-update-utmp writes.
AUDIT_SERVICE_TYPES = {"SERVICE_START": "start", "SERVICE_STOP": "stop"}
AUDIT_SYSTEM_TYPES = {"SYSTEM_BOOT": "boot", "SYSTEM_SHUTDOWN": "shutdown", "SYSTEM_RUNLEVEL": "runlevel"}
AUDIT_ADMIN_TYPES = set(AUDIT_ACCOUNT_TYPES) | set(AUDIT_SERVICE_TYPES) | set(AUDIT_SYSTEM_TYPES) | {"CONFIG_CHANGE"}
ADMIN_COMPANIONS = {"SYSCALL", "PROCTITLE"}
# Kernel audit settings a CONFIG_CHANGE `op=set` record (or an older record without op) names.
AUDIT_SETTINGS = ("audit_enabled", "audit_pid", "audit_failure", "audit_rate_limit", "audit_backlog_limit",
                  "audit_backlog_wait_time", "audit_lost")
_PLACEHOLDERS = {None, "", "?", "(null)", "(none)", "unset", "(unknown)"}


def _user_message_field(record: AuditRecord, key: str) -> str | None:
    """A field of the quoted user message (`msg='key=value ...'`). The tokenizer reads its first pair as `msg`
    with the opening quote and its last value with the closing quote; both are recovered here."""
    opener = record.fields.get("msg", "")
    value = opener[len(key) + 2:] if opener.startswith(f"'{key}=") else record.fields.get(key)
    value = value.strip("'") if isinstance(value, str) else value
    return None if value in _PLACEHOLDERS else value


def _record_outcome(record: AuditRecord) -> Outcome:
    result = (_user_message_field(record, "res") or "").strip("'\"").lower()
    return (Outcome.success if result in {"success", "yes", "1"}
            else Outcome.failure if result in {"failed", "failure", "no", "0"} else Outcome.unknown)


def _header_process_fields(origin: str, record: AuditRecord) -> dict:
    """Actor identity from a user-space record's own header and enrichment (absent stays absent)."""
    fields = {}
    pid = record.fields.get("pid")
    if pid and pid.isdigit():
        fields["process.pid"] = fv(int(pid), f"{origin}.pid")
    if "uid" in record.fields:
        fields["process.uid"] = fv(record.fields["uid"], f"{origin}.uid")
    auid = record.fields.get("auid")
    if auid not in {None, "", "-1", "4294967295"}:
        fields["process.auid"] = fv(auid, f"{origin}.auid")
    session_id = record.fields.get("ses")
    if session_id and session_id.isdigit() and session_id != "4294967295":
        fields["process.session_id"] = fv(int(session_id), f"{origin}.ses")
    for name, key in (("process.user", "UID"), ("process.login_user", "AUID")):
        if record.enriched.get(key) not in _PLACEHOLDERS:
            fields[name] = fv(record.enriched[key], f"{origin}:enriched.{key}")
    executable = _user_message_field(record, "exe")
    if executable:
        fields["process.executable"] = fv(executable, f"{origin}.exe")
    return fields


def service_name(unit: str) -> str:
    """A unit's service name for matching: lower case, without the unit type suffix or template instance."""
    name = unit.lower()
    for suffix in (".service", ".socket"):
        name = name.removesuffix(suffix)
    return name.split("@", 1)[0]


def normalize_audit_admin_group(host: str, members: list[tuple[dict, AuditRecord]]) -> list[TypedEvent]:
    """One typed event per account, service, system-state or audit-configuration record of a group. A SYSCALL
    record of the same group (the netlink send that carried a configuration change) adds the sender's identity."""
    companions = [(hit, record) for hit, record in members if record.type in ADMIN_COMPANIONS]
    syscall = next(((hit, record) for hit, record in companions if record.type == "SYSCALL"), None)
    out = []
    for hit, record in sorted(((h, r) for h, r in members if r.type in AUDIT_ADMIN_TYPES),
                              key=lambda item: item[0]["_id"]):
        origin = f"{hit['_id']}:event.original#auditd:{record.type}"
        refs = [_ref(hit)] + [_ref(item_hit) for item_hit, _record in companions]
        fields = {"audit.record_type": fv(record.type, f"{origin}.type"), **_audit_boot_field(members),
                  **_audit_time(hit["_id"], record.ts)}
        fields.update(_header_process_fields(origin, record))
        outcome = _record_outcome(record)
        if record.type in AUDIT_ACCOUNT_TYPES:
            family = "account_change"
            fields["account.action"] = fv(AUDIT_ACCOUNT_TYPES[record.type], f"{origin}.type")
            op = _user_message_field(record, "op")
            if op and " " not in op:
                fields["account.op"] = fv(op, f"{origin}.op")
            for name, key in (("account.name", "acct"), ("account.id", "id"), ("account.group", "grp")):
                value = _user_message_field(record, key)
                if value:
                    fields[name] = fv(value, f"{origin}.{key}")
            address = _user_message_field(record, "addr")
            if address:
                fields["source.ip"] = fv(address, f"{origin}.addr")
        elif record.type in AUDIT_SERVICE_TYPES:
            family = "service_change"
            unit = _user_message_field(record, "unit")
            if not unit:
                raise ValueError(f"{record.type} record without a unit")
            fields.update({"service.unit": fv(unit, f"{origin}.unit"),
                           "service.name": fv(service_name(unit), f"{origin}.unit"),
                           "service.job": fv(AUDIT_SERVICE_TYPES[record.type], f"{origin}.type"),
                           "service.job_phase": fv("done", f"{origin}.type"),
                           "service.scope": fv("system", f"{origin}.type"),
                           "service.source": fv("audit", f"{origin}.type")})
        elif record.type in AUDIT_SYSTEM_TYPES:
            family = "system_state"
            fields["system.event"] = fv(AUDIT_SYSTEM_TYPES[record.type], f"{origin}.type")
            for name, key in (("system.runlevel", "new-level"), ("system.previous_runlevel", "old-level")):
                value = _user_message_field(record, key)
                if value:
                    fields[name] = fv(value, f"{origin}.{key}")
        else:
            family = "audit_config"
            setting = next((key for key in AUDIT_SETTINGS if key in record.fields), None)
            op = (record.fields.get("op") or "").strip("'\"") or ("set" if setting else "")
            if not op:
                raise ValueError("CONFIG_CHANGE record names neither an operation nor a setting")
            fields["audit.config.op"] = fv(op, f"{origin}.op")
            if setting:
                fields["audit.config.setting"] = fv(setting, f"{origin}.{setting}")
                fields["audit.config.value"] = fv(record.fields[setting], f"{origin}.{setting}")
                if "old" in record.fields:
                    # numeric: the parser's hex decoding of `old` (meant for other record types) must not apply
                    fields["audit.config.old"] = fv(record.raw_fields["old"][0], f"{origin}.old")
            if record.fields.get("key") not in _PLACEHOLDERS:
                fields["audit.key"] = fv(record.fields["key"], f"{origin}.key")
            if record.fields.get("list", "").isdigit():
                fields["audit.config.list"] = fv(record.fields["list"], f"{origin}.list")
            if syscall is not None:
                fields.update(_syscall_process_fields(syscall[0]["_id"], syscall[1]))
        out.append(TypedEvent(id=event_id(family, refs), family=family, ts=datetime.fromtimestamp(record.ts, UTC),
                              host=host or None, outcome=outcome, fields=fields, raw=refs,
                              normalizer=NORMALIZER_VERSION))
    return out


def normalize_socket_group(host: str, members: list[tuple[dict, AuditRecord]], syscall: str) -> TypedEvent:
    """One net_socket event from a socket SYSCALL plus its SOCKADDR. connect() records the remote
    endpoint, accept() the peer, bind() the local address. A non-blocking connect that returns
    EINPROGRESS was started, not refused, so its outcome is unknown rather than failed."""
    by_type = {r.type: (h, r) for h, r in members if r.type in SOCKET_COMPANIONS}
    hs, rs = by_type["SYSCALL"]
    sid = hs["_id"]
    refs = [_ref(h) for h, r in members if r.type in SOCKET_COMPANIONS]
    f = {"socket.syscall": fv(syscall, f"{sid}:event.original#auditd:SYSCALL.arch+syscall"),
         "audit.serial": fv(rs.serial, f"{sid}:event.original#auditd:msg.serial"),
         **_audit_boot_field(members), **_audit_time(sid, rs.ts),
         **_syscall_process_fields(sid, rs)}
    if rs.fields.get("key") not in (None, "(null)"):
        f["audit.key"] = fv(rs.fields["key"], f"{sid}:event.original#auditd:SYSCALL.key")
    caveats = []
    if "SOCKADDR" in by_type:
        ha, ra = by_type["SOCKADDR"]
        addr = parse_sockaddr(ra.fields.get("saddr", ""))
        origin = f"{ha['_id']}:event.original#auditd:SOCKADDR.saddr"
        if addr.ip is None:
            raise Skip(f"audit {syscall} on a non-IP socket family ({addr.family})")
        f["socket.family"] = fv(addr.family, origin)
        side = {"connect": "destination", "accept": "source", "accept4": "source", "bind": "socket.local"}[syscall]
        f[f"{side}.ip"] = fv(addr.ip, origin)
        f[f"{side}.port"] = fv(addr.port, origin)
    else:
        caveats.append("SOCKADDR companion not retrieved: socket address unknown")
    succ, exit_code = rs.fields.get("success"), rs.fields.get("exit")
    if succ == "yes":
        outcome = Outcome.success
    elif succ == "no" and exit_code == EINPROGRESS and syscall == "connect":
        outcome = Outcome.unknown
        caveats.append("non-blocking connect returned EINPROGRESS: the connection was started; completion is "
                       "not recorded")
    elif succ == "no":
        outcome = Outcome.failure
    else:
        outcome = Outcome.unknown
    if exit_code:
        f["socket.exit"] = fv(exit_code, f"{sid}:event.original#auditd:SYSCALL.exit")
    # the audit header's own epoch, not the shipper's @timestamp: joins with sensor clocks need the kernel time
    return TypedEvent(id=event_id("net_socket", refs), family="net_socket", ts=datetime.fromtimestamp(rs.ts, UTC),
                      host=host or None, outcome=outcome, fields=f, raw=refs, normalizer=NORMALIZER_VERSION,
                      caveats=caveats)


def normalize_observed_group(host: str, members: list[tuple[dict, AuditRecord]]) -> TypedEvent | None:
    """One process_observed event from an audit group whose SYSCALL record becomes no other typed event (a read-only
    open, a connect on a local socket, any call no family models): the process that made the call, as the kernel
    recorded it at that instant (pid, parent, executable, ids, audit session). It is not an action claim; process
    lineage reads it (`romulus.detect.observed`). It views the SYSCALL record only. None when the group has no
    SYSCALL record naming the pid, parent and executable."""
    found = next(((hit, record) for hit, record in members if record.type == "SYSCALL"), None)
    if found is None:
        return None
    hs, rs = found
    if not (rs.fields.get("pid", "").isdigit() and rs.fields.get("ppid", "").isdigit() and rs.fields.get("exe")):
        return None
    sid = hs["_id"]
    refs = [_ref(hs)]
    f = {"audit.serial": fv(rs.serial, f"{sid}:event.original#auditd:msg.serial"),
         **_audit_boot_field(members), **_audit_time(sid, rs.ts), **_syscall_process_fields(sid, rs)}
    if rs.enriched.get("SYSCALL"):
        f["audit.syscall"] = fv(rs.enriched["SYSCALL"], f"{sid}:event.original#auditd:enriched.SYSCALL")
    if rs.fields.get("key") not in (None, "(null)"):
        f["audit.key"] = fv(rs.fields["key"], f"{sid}:event.original#auditd:SYSCALL.key")
    succ = rs.fields.get("success")
    outcome = Outcome.success if succ == "yes" else Outcome.failure if succ == "no" else Outcome.unknown
    return TypedEvent(id=event_id("process_observed", refs), family="process_observed",
                      ts=datetime.fromtimestamp(rs.ts, UTC), host=host or None, outcome=outcome, fields=f, raw=refs,
                      normalizer=NORMALIZER_VERSION)


def normalize_exec_group(host: str, members: list[tuple[dict, AuditRecord]]) -> TypedEvent:
    """Build one process_exec event from the EXECVE record plus whatever companions are present.
    Missing SYSCALL means uid/ppid/success are unknown (caveat), not defaulted."""
    by_type: dict[str, tuple[dict, AuditRecord]] = {}
    execs: list[tuple[dict, AuditRecord]] = []
    refs = []
    for hit, record in members:
        if record.type not in EXEC_COMPANIONS:
            continue
        refs.append(_ref(hit))
        if record.type == "EXECVE":
            execs.append((hit, record))
        else:
            by_type[record.type] = (hit, record)
    if not execs:
        raise Skip("no EXECVE record in group")
    h_exec, r_exec = merge_execve(execs)
    by_type["EXECVE"] = (h_exec, r_exec)
    argv, argv_problem = execve_argv(r_exec)
    nid = h_exec["_id"]
    f = {
        "process.argv": fv(argv, f"{nid}:event.original#auditd:EXECVE.a*"),
        "process.args_count": fv(len(argv), f"{nid}:event.original#auditd:EXECVE.argc"),
        "audit.serial": fv(r_exec.serial, f"{nid}:event.original#auditd:msg.serial"),
        **_audit_boot_field(members), **_audit_time(nid, r_exec.ts),
    }
    caveats = []
    if argv_problem:
        # what arrived is kept as evidence; rules see the flag and say the command line is incomplete
        f["process.argv_complete"] = fv(False, f"{nid}:event.original#auditd:EXECVE.a*")
        caveats.append(f"{INCOMPLETE_ARGV_CAVEAT}: {argv_problem}")
    outcome = Outcome.unknown
    if "SYSCALL" in by_type:
        hs, rs = by_type["SYSCALL"]
        f.update(_syscall_process_fields(hs["_id"], rs))
        succ = rs.fields.get("success")
        outcome = Outcome.success if succ == "yes" else Outcome.failure if succ == "no" else Outcome.unknown
    else:
        caveats.append("SYSCALL companion not retrieved: uid/ppid/executable/outcome unknown")
    if "CWD" in by_type:
        hc, rc = by_type["CWD"]
        f["process.cwd"] = fv(rc.fields.get("cwd"), f"{hc['_id']}:event.original#auditd:CWD.cwd")
    used, exec_caveats = _exec_file_fields(f, members, argv, by_type.get("CWD"))
    refs += [_ref(h) for h in used]
    caveats += exec_caveats
    return TypedEvent(id=event_id("process_exec", refs), family="process_exec", ts=_ts(h_exec["_source"]["@timestamp"]),
                      host=host or None, outcome=outcome, fields=f, raw=refs, normalizer=NORMALIZER_VERSION,
                      caveats=caveats)


# PATH records: one per name a system call looked up, numbered by `item` in lookup order. `nametype` says what
# the call did with it (NORMAL: used an existing file; CREATE/DELETE: added or removed a directory entry; PARENT:
# the directory holding a created or deleted entry; UNKNOWN: the lookup failed).
_NO_NAME = {"", "(null)", "(none)"}


def _path_items(members: list[tuple[dict, AuditRecord]]) -> dict[int, tuple[dict, AuditRecord]]:
    items: dict[int, tuple[dict, AuditRecord]] = {}
    for hit, record in members:
        if record.type != "PATH":
            continue
        number = record.fields.get("item", "")
        if not number.isdigit():
            raise AuditParseError("PATH record without an item number")
        if int(number) in items:
            raise AuditParseError(f"ambiguous event group, duplicate PATH item {number}")
        items[int(number)] = (hit, record)
    return items


def _lexical(path: str) -> str:
    normalized = posixpath.normpath(path)
    return "/" + normalized.lstrip("/")


def _resolve(name: str | None, dirfd: int | None, syscall: AuditRecord, cwd: tuple[dict, AuditRecord] | None,
             parents: list[tuple[dict, AuditRecord]]) -> tuple[str | None, list[dict], str, str]:
    """(absolute path, records used to place it, origin suffix, why it could not be placed) for a PATH name.

    A relative name is relative to the working directory unless the call passed a directory descriptor other than
    the working directory's; that descriptor's path is not recorded, so such a name is never guessed. Without a
    CWD record, a bare name is placed under its PARENT record when that is absolute (for a bare name the kernel
    writes the working directory there)."""
    if name is None or name in _NO_NAME:
        return None, [], "", "the kernel recorded no name for the file"
    if name.startswith("/"):
        return _lexical(name), [], "", ""
    if dirfd is not None and syscall.fields.get(f"a{dirfd}", "").lower() not in AT_FDCWD:
        return None, [], "", ("the relative name is resolved against a directory descriptor whose path is not "
                              "recorded")
    if cwd is not None and cwd[1].fields.get("cwd", "").startswith("/"):
        return _lexical(posixpath.join(cwd[1].fields["cwd"], name)), [cwd[0]], "+CWD.cwd", ""
    if "/" not in name:
        dirs = {(record.fields.get("name") or ""): hit for hit, record in parents
                if (record.fields.get("name") or "").startswith("/")}
        if len(dirs) == 1:
            directory, hit = next(iter(dirs.items()))
            return _lexical(posixpath.join(directory, name)), [hit], "+PATH(PARENT).name", ""
    return None, [], "", "the relative name has no recorded working directory"


def _owner_fields(prefix: str, hit: dict, record: AuditRecord) -> dict:
    """Inode identity, mode and ownership of a PATH item as the kernel recorded them at the call."""
    origin = f"{hit['_id']}:event.original#auditd:PATH"
    out = {}
    for name, key in (("inode", "inode"), ("device", "dev"), ("mode", "mode"), ("owner.id", "ouid"),
                      ("group.id", "ogid")):
        value = record.fields.get(key)
        if value not in (None, ""):
            out[f"{prefix}.{name}"] = fv(int(value) if key == "inode" and value.isdigit() else value,
                                         f"{origin}.{key}")
    for name, key in (("owner.name", "OUID"), ("group.name", "OGID")):
        if record.enriched.get(key):
            out[f"{prefix}.{name}"] = fv(record.enriched[key], f"{origin}:enriched.{key}")
    return out


def _exec_file_fields(f: dict, members: list[tuple[dict, AuditRecord]], argv: list[str],
                      cwd: tuple[dict, AuditRecord] | None) -> tuple[list[dict], list[str]]:
    """Add the executed file's inode, mode and ownership from the exec's PATH records.

    PATH item 0 is the file the exec call named: the program, or a `#!` script. For a script the kernel rewrites
    argv to `<interpreter> [arg] <script> ...` and looks the interpreter up as a later item, so item 0 is the
    script when its name is argv[1] or argv[2] and a later item's name is argv[0]; that later item is the
    interpreter. Returns the PATH records used and caveats."""
    try:
        items = _path_items(members)
    except AuditParseError as e:
        return [], [f"exec PATH records not used: {e}"]
    if 0 not in items:
        return [], ["PATH record of the executed file not retrieved: its owner and mode are unknown"]
    hit, record = items[0]
    used = [hit]
    name = record.fields.get("name")
    f.update(_owner_fields("process.exec_file", hit, record))
    path, extra, suffix, _why = _resolve(name, None, record, cwd, [])
    if path:
        f["process.exec_file.path"] = fv(path, f"{hit['_id']}:event.original#auditd:PATH.name{suffix}")
        used += extra
    interpreter = None
    if argv and name and name != argv[0] and name in argv[1:3]:
        interpreter = next(((h, r) for i, (h, r) in sorted(items.items())
                            if i > 0 and r.fields.get("name") == argv[0]), None)
    role_origin = f"{hit['_id']}:event.original#auditd:PATH.item+EXECVE.a0"
    f["process.exec_file.role"] = fv("script" if interpreter else "executable", role_origin)
    if interpreter is not None:
        ih, ir = interpreter
        used.append(ih)
        f.update(_owner_fields("process.interpreter_file", ih, ir))
        ipath, iextra, isuffix, _ = _resolve(ir.fields.get("name"), None, ir, cwd, [])
        if ipath:
            f["process.interpreter_file.path"] = fv(ipath, f"{ih['_id']}:event.original#auditd:PATH.name{isuffix}")
            used += iextra
    return list({h["_id"]: h for h in used}.values()), []


# What a call did to each named file, by kind: the PATH nametypes that name a changed file.
_CHANGE_NAMETYPES = {"truncate": ("NORMAL",), "attributes": ("NORMAL",), "delete": ("DELETE",),
                     "create": ("CREATE",), "link": ("CREATE",)}
_KIND_CHANGE = {"truncate": "content", "attributes": "attributes", "delete": "delete", "create": "create",
                "link": "link"}


def _open_intent(call: FileCall, rs: AuditRecord) -> tuple[int | None, str | None]:
    """(open flags, the register they were read from); flags None when the call does not record them."""
    if call.name == "creat":
        return O_CREAT | O_WRONLY | O_TRUNC, None
    if call.flags is None:
        return None, None
    return syscall_arg(rs, call.flags), f"a{call.flags}"


def _file_targets(call: FileCall, items: dict[int, tuple[dict, AuditRecord]], failed: bool,
                  flags: int | None) -> list[tuple[tuple[dict, AuditRecord], str | None, int]]:
    """(PATH item, change, name slot) for each file the call changed. The name slot is 0 for the call's only or
    old name and 1 for its new name (it picks the directory-descriptor argument). A change of None means the
    records do not say what changed."""
    children = [items[i] for i in sorted(items) if items[i][1].fields.get("nametype") != "PARENT"]

    def nametype(item):
        return item[1].fields.get("nametype")

    # a failed lookup is recorded as UNKNOWN: it names the file the call tried to change
    attempted = [c for c in children if failed and nametype(c) == "UNKNOWN"]
    if call.kind == "open":
        creates = [c for c in children if nametype(c) == "CREATE"]
        if creates:
            return [(c, "create", 0) for c in creates]
        if flags is None:
            return [(c, None, 0) for c in children]
        if (flags & O_ACCMODE) in (O_WRONLY, O_RDWR) or flags & O_TRUNC:
            return ([(c, "content", 0) for c in children if nametype(c) == "NORMAL"]
                    + [(c, "create" if flags & O_CREAT else "content", 0) for c in attempted])
        return []
    if call.kind == "rename":
        creates = [c for c in children if nametype(c) == "CREATE"]
        deletes = [c for c in children if nametype(c) == "DELETE"]
        if creates:
            new_names = {c[1].fields.get("name") for c in creates}
            # a DELETE item under the new name is the file the rename replaced; its path is the target's
            return ([(c, "rename_target", 1) for c in creates]
                    + [(d, "rename_source", 0) for d in deletes if d[1].fields.get("name") not in new_names])
        if len(children) == 2:
            # rename looks the old name up before the new one, so the items are in that order
            return [(children[0], "rename_source", 0), (children[1], "rename_target", 1)]
        return [(c, None, 0) for c in children]
    wanted = _CHANGE_NAMETYPES[call.kind]
    slot = 1 if call.kind == "link" else 0
    return ([(c, _KIND_CHANGE[call.kind], slot) for c in children if nametype(c) in wanted]
            + [(c, _KIND_CHANGE[call.kind], slot) for c in attempted])


def normalize_module_group(host: str, members: list[tuple[dict, AuditRecord]], syscall: str | None) -> TypedEvent:
    """Module-load/unload observations: names come from KERN_MODULE, paths only from PATH.

    init_module receives memory, not a pathname. A finit_module PATH can identify its fd's file;
    without it, a module name is never invented from the command line or a pointer argument.
    """
    found = next(((hit, record) for hit, record in members if record.type == "SYSCALL"), None)
    module = next(((hit, record) for hit, record in members if record.type == "KERN_MODULE"), None)
    hit, record = found or module
    origin = f"{hit['_id']}:event.original#auditd:{record.type}"
    fields = {"audit.serial": fv(record.serial, f"{origin}.msg.serial"),
              **_audit_boot_field(members), **_audit_time(hit["_id"], record.ts)}
    if found:
        fields.update(_syscall_process_fields(hit["_id"], record))
    op = "unload" if syscall == "delete_module" else "load" if syscall else None
    if module:
        mh, mr = module
        morigin = f"{mh['_id']}:event.original#auditd:KERN_MODULE"
        if mr.fields.get("name"):
            fields["module.name"] = fv(mr.fields["name"], f"{morigin}.name")
        if mr.fields.get("op") in {"load", "unload"}:
            if op and op != mr.fields["op"]:
                raise AuditParseError("module operation disagrees between SYSCALL and KERN_MODULE")
            op = mr.fields["op"]
    if op:
        fields["module.op"] = fv(op, f"{origin}.arch+syscall" if syscall else f"{origin}.type+op")
    refs = [_ref(h) for h, r in members if r.type in {"SYSCALL", "KERN_MODULE"}]
    caveats = [] if op else ["module operation unknown: the SYSCALL companion and an explicit operation are absent"]
    if syscall == "finit_module":
        items = _path_items(members)
        paths = [(h, r) for h, r in items.values() if r.fields.get("nametype") != "PARENT"]
        resolved = []
        cwd = next(((h, r) for h, r in members if r.type == "CWD"), None)
        for ph, pr in paths:
            path, used, suffix, _why = _resolve(pr.fields.get("name"), None, record, cwd, [])
            if path:
                resolved.append((path, ph, used, suffix))
        if len(resolved) == 1:
            path, ph, used, suffix = resolved[0]
            fields["module.path"] = fv(path, f"{ph['_id']}:event.original#auditd:PATH.name{suffix}")
            refs += [_ref(ph), *[_ref(h) for h in used]]
        else:
            caveats.append("module file path unknown: no unique resolved PATH record names it")
    outcome = Outcome.success if record.fields.get("success") == "yes" else (
        Outcome.failure if record.fields.get("success") == "no" else Outcome.unknown)
    refs = list({ref.key: ref for ref in refs}.values())
    return TypedEvent(id=event_id("kernel_module", refs), family="kernel_module",
                      ts=datetime.fromtimestamp(record.ts, UTC), host=host or None, outcome=outcome,
                      fields=fields, raw=refs, normalizer=NORMALIZER_VERSION, caveats=caveats)


def normalize_file_group(host: str, members: list[tuple[dict, AuditRecord]], call: FileCall) -> list[TypedEvent]:
    """file_change events from a SYSCALL record of a file-changing call and its PATH records: one per changed file.

    An open is a change only with write intent (write access, O_TRUNC) or when it created the file; a read-only
    open is retained as file_access only with a recorded non-placeholder watch key. What cannot be decided stays
    absent, never defaulted: a file whose name cannot be placed has
    no `file.path`, and a call whose records do not say what changed has no `file.change`; rules count both as
    missing fields. A failed call is kept with outcome failure: it is an attempt."""
    by_type = {r.type: (h, r) for h, r in members if r.type in ("SYSCALL", "CWD", "PROCTITLE")}
    hs, rs = by_type["SYSCALL"]
    sid = hs["_id"]
    origin = f"{sid}:event.original#auditd:SYSCALL"
    items = _path_items(members)
    succ = rs.fields.get("success")
    outcome = Outcome.success if succ == "yes" else Outcome.failure if succ == "no" else Outcome.unknown
    base = {"file.syscall": fv(call.name, f"{origin}.arch+syscall"),
            "audit.serial": fv(rs.serial, f"{sid}:event.original#auditd:msg.serial"),
            **_audit_boot_field(members), **_audit_time(sid, rs.ts), **_syscall_process_fields(sid, rs)}
    if rs.fields.get("key") not in (None, "(null)"):
        base["audit.key"] = fv(rs.fields["key"], f"{origin}.key")
    if rs.fields.get("exit"):
        base["file.exit"] = fv(rs.fields["exit"], f"{origin}.exit")
    caveats = []
    expected = rs.fields.get("items", "")
    if expected.isdigit() and int(expected) != len(items):
        caveats.append(f"{len(items)} of the {expected} PATH records of this call were retrieved")
    flags = None
    if call.kind == "open":
        flags, register = _open_intent(call, rs)
        if flags is not None and register:
            base["file.open_flags"] = fv(rs.fields[register], f"{origin}.{register}")
        if flags is not None and flags & O_TMPFILE_BIT:
            raise Skip("audit open of an unnamed temporary file (O_TMPFILE)")
        if flags is None:
            caveats.append(f"{call.name} does not record its open flags: whether the file was opened for writing "
                           "is unknown")
    if call.mode is not None and (mode := syscall_arg(rs, call.mode)) is not None:
        base["file.new_mode"] = fv(f"{mode & 0o7777:04o}", f"{origin}.a{call.mode}")
    if call.owner is not None:
        for name, index in (("file.new_owner.id", call.owner[0]), ("file.new_group.id", call.owner[1])):
            value = syscall_arg(rs, index)
            if value is not None and value not in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):    # -1 leaves it unchanged
                base[name] = fv(str(value), f"{origin}.a{index}")
    targets = [] if call.by_fd else _file_targets(call, items, outcome == Outcome.failure, flags)
    write = flags is not None and ((flags & O_ACCMODE) in (O_WRONLY, O_RDWR) or bool(flags & O_TRUNC))
    read = call.kind == "open" and flags is not None and not write and not targets
    family = "file_access" if read else "file_change"
    if read:
        if str(rs.fields.get("key") or "").casefold() in WATCH_PLACEHOLDERS:
            raise Skip("audit open without write intent")
        base["file.access"] = fv("read", f"{origin}.arch+syscall+key")
        targets = [(item, None, 0) for item in items.values()
                   if item[1].fields.get("nametype") in {"NORMAL", "UNKNOWN"}]
    extra = [_ref(by_type["PROCTITLE"][0])] if "PROCTITLE" in by_type else []
    if not targets:
        why = ("the call acts on an open file descriptor, so the kernel records no path for the file" if call.by_fd
               else "no PATH record names the changed file")
        fields = dict(base)
        change = ("content" if write else None) if call.kind == "open" else _KIND_CHANGE.get(call.kind)
        if change:
            fields["file.change"] = fv(change, f"{origin}.syscall")
        refs = [_ref(hs), *extra]
        return [TypedEvent(id=event_id(family, refs), family=family,
                           ts=datetime.fromtimestamp(rs.ts, UTC), host=host or None, outcome=outcome, fields=fields,
                           raw=refs, normalizer=NORMALIZER_VERSION, caveats=[*caveats, f"file path unknown: {why}"])]
    cwd = by_type.get("CWD")
    # a PARENT record places a bare name only when every PATH record of the call is present: with one missing,
    # the PARENT seen may belong to another of the call's names
    complete = not (expected.isdigit() and int(expected) != len(items))
    parents = [items[i] for i in sorted(items) if items[i][1].fields.get("nametype") == "PARENT"] if complete else []
    events = []
    for (ph, pr), change, slot in targets:
        fields = dict(base)
        event_caveats = list(caveats)
        porigin = f"{ph['_id']}:event.original#auditd:PATH"
        path, used, suffix, why = _resolve(pr.fields.get("name"), call.dirfd[slot], rs, cwd, parents)
        if path:
            fields["file.path"] = fv(path, f"{porigin}.name{suffix}")
        else:
            event_caveats.append(f"file path unknown: {why}")
        if change:
            fields["file.change"] = fv(change, f"{origin}.syscall+{porigin}.nametype")
        if pr.fields.get("nametype"):
            fields["file.nametype"] = fv(pr.fields["nametype"], f"{porigin}.nametype")
        fields.update(_owner_fields("file", ph, pr))
        refs = list({r.key: r for r in [_ref(hs), _ref(ph), *[_ref(h) for h in used], *extra]}.values())
        events.append(TypedEvent(id=event_id(family, refs), family=family,
                                 ts=datetime.fromtimestamp(rs.ts, UTC), host=host or None, outcome=outcome,
                                 fields=fields, raw=refs, normalizer=NORMALIZER_VERSION, caveats=event_caveats))
    return events


# ---------------------------------------------------------------------------------------------
# systemd.journal: sshd / sudo messages; audit copies are duplicates of linux.audit
# ---------------------------------------------------------------------------------------------

_SSH_OK = re.compile(r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|gssapi-with-mic) for "
                     r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
# sshd prints an attempted account name verbatim, so the name is matched greedily and the source is the last
# "from <ip> port <n>" before the fixed suffix: a name such as "x from 192.0.2.1 port 1" cannot move the source.
_SSH_FAIL = re.compile(r"^Failed (?P<method>[\w/-]+) for (?P<invalid>invalid user )?(?P<user>.*) from "
                       r"(?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)(?: ssh2)?(?:: .*)?$")
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?$")
_SSH_PREAUTH = re.compile(r"^(?:Connection closed by|Disconnected from) (?P<kind>authenticating|invalid) user "
                          r"(?P<user>.*) (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) \[preauth\]$")
_SSH_MAXTRIES = re.compile(r"^(?:error: )?maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
                           r"(?P<user>.*) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)(?: ssh2)? \[preauth\]$")
# (pattern, outcome, phase). An attempt's phase: an authentication decision ("Accepted"/"Failed"), a lookup of an
# account name that does not exist, a connection closed before authentication completed, or sshd ending a
# connection that used up its authentication attempts.
_SSH_FORMS = ((_SSH_OK, Outcome.success, "authentication"), (_SSH_FAIL, Outcome.failure, "authentication"),
              (_SSH_INVALID, Outcome.failure, "user_lookup"), (_SSH_PREAUTH, Outcome.failure, "preauth_disconnect"),
              (_SSH_MAXTRIES, Outcome.failure, "max_attempts"))
# systemd catalog message ids of unit job messages: (job type, phase).
_UNIT_JOB_IDS = {"9d1aaa27d60140bd96365438aad20286": ("stop", "done"),
                 "de5b426a63be47a7b6ac3eaac82e2f6f": ("stop", "begun"),
                 "39f53479d3a045ac8e11786248231fbf": ("start", "done"),
                 "7d4958e842da4a758f6c1cdc7b36dcc5": ("start", "begun")}
# Newer systemd names the unit in the message ("Stopped auditd.service - Security Auditing Service.").
_UNIT_JOB_TEXT = re.compile(r"^(?P<verb>Stopped|Stopping|Started|Starting|Reached target|Stopped target) "
                            r"(?P<unit>[\w@:.\\-]+\.(?:service|socket|target|timer|path|mount|scope|slice))"
                            r"(?: - .*|\.\.\.|\.)?$")
_UNIT_EXIT = re.compile(r"^(?P<unit>[\w@:.\\-]+): (?:Main process exited, code=(?P<code>killed|dumped), "
                        r"status=\S+|Failed with result '(?P<result>signal|core-dump)')\.?$")
# Process names sshd runs as (OpenSSH 9.8 splits per-session work into sshd-session and sshd-auth).
_SSHD_COMMS = ("sshd",)
_UNIT_JOB_VERBS = {"Stopped": ("stop", "done"), "Stopping": ("stop", "begun"), "Started": ("start", "done"),
                   "Starting": ("start", "begun"), "Reached target": ("start", "done"),
                   "Stopped target": ("stop", "done")}
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<fail>.*?incorrect password attempts?|command not allowed|"
                   r"user NOT in sudoers) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<target>\S+) ;"
                   r"(?: COMMAND=(?P<cmd>.*))?$")


def normalize_journal(hit: dict, boots_seen: list | None = None) -> TypedEvent:
    """One journald record. With `boots_seen`, the record's boot observations (see `_journal_observations`) are
    appended to it first, whatever becomes of the record."""
    src = hit["_source"]
    original = _get(src, "event.original")
    if not original:
        # without the structured journal record we cannot tell an sshd login from anything else
        raise ValueError("journal record missing authoritative event.original")
    try:
        j = json.loads(original)
    except json.JSONDecodeError as e:
        raise ValueError(f"journal event.original is not JSON: {e}") from e
    if not isinstance(j, dict):
        raise TypeError("journal event.original is not a JSON object")
    prefix = f"{hit['_id']}:event.original#journal:"
    return _journal_event(hit, j, lambda spec: prefix + spec, boots_seen)


def _journal_event(hit: dict, j: dict, o: Callable[[str], str], boots_seen: list | None = None, *,
                   copy_reason: str | None = None, kind: str = "journal") -> TypedEvent:
    """The typed event of one journal record `j` (journal field names), whatever shape carried it. `o(spec)` is the
    origin of a journal field spec ("MESSAGE~sshd", "JOB_TYPE+JOB_RESULT"). A copy of an audit record raises
    AuditCopy (with `copy_reason` when given); a line of an identifier no rule reads is skipped, counted by `kind`
    and identifier."""
    src = hit["_source"]
    if boots_seen is not None:
        boots_seen.extend(_journal_observations(hit, j))
    if j.get("_TRANSPORT") == "audit" or j.get("SYSLOG_IDENTIFIER") == "audit":
        raise AuditCopy(j) if copy_reason is None else AuditCopy(j, copy_reason)
    ident = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM")
    msg = j.get("MESSAGE") or src.get("message") or ""
    ref = _ref(hit)
    host = j.get("_HOSTNAME") or _get(src, "host.name")
    base = {"journal.identifier": fv(ident, o("SYSLOG_IDENTIFIER")),
            "journal.unit": fv(j.get("_SYSTEMD_UNIT"), o("_SYSTEMD_UNIT"))}
    if _journal_boot(j):
        base["host.boot.id"] = fv(_journal_boot(j), o("_BOOT_ID"))
    if ident == "sshd":
        # SYSLOG_IDENTIFIER is chosen by the writer; journald's own _COMM/_EXE/_SYSTEMD_UNIT are not. When any of
        # them is recorded, one must name sshd, or the line came from another program.
        trusted = [str(v) for v in (j.get("_COMM"), basename_of(j.get("_EXE")), j.get("_SYSTEMD_UNIT")) if v]
        if trusted and not any(v.startswith(_SSHD_COMMS) or v.startswith(("ssh.service", "ssh@", "sshd@"))
                               for v in trusted):
            raise Skip("sshd-identified journal line written by another program")
        for rx, outcome, phase in _SSH_FORMS:
            m = rx.match(msg)
            if m:
                g = m.groupdict()
                origin = o("MESSAGE~sshd")
                f = {**base,
                     "auth.service": fv("sshd", o("SYSLOG_IDENTIFIER")),
                     "auth.method": fv(g.get("method"), origin),
                     "auth.phase": fv(phase, origin),
                     "auth.user_valid": fv(not (g.get("invalid") or g.get("kind") == "invalid"
                                                or rx is _SSH_INVALID), origin),
                     "source.ip": fv(g["ip"], origin)}
                if g["user"]:
                    f["user.name"] = fv(g["user"], origin)
                if g.get("port"):
                    f["source.port"] = fv(int(g["port"]), origin)
                return TypedEvent(id=event_id("auth", [ref]), family="auth", ts=_ts(src["@timestamp"]), host=host,
                                  outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION)
        raise Skip("sshd message without an authentication outcome")
    if ident == "systemd":
        return _unit_job(hit, j, msg, base, host, o)
    if ident == "sudo":
        m = _SUDO.match(msg)
        if m:
            g = m.groupdict()
            f = {**base,
                 "auth.service": fv("sudo", o("SYSLOG_IDENTIFIER")),
                 "user.name": fv(g["user"], o("MESSAGE~sudo")),
                 "auth.target_user": fv(g["target"], o("MESSAGE~sudo")),
                 "sudo.command": fv(g.get("cmd"), o("MESSAGE~sudo")),
                 "process.cwd": fv(g.get("pwd"), o("MESSAGE~sudo"))}
            outcome = Outcome.failure if g.get("fail") else Outcome.success
            return TypedEvent(id=event_id("privilege_use", [ref]), family="privilege_use", ts=_ts(src["@timestamp"]),
                              host=host, outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION)
        raise Skip("sudo message not a command record")
    raise Skip(f"{kind} identifier {ident!r} is not normalized")


def basename_of(path) -> str:
    return str(path).rsplit("/", 1)[-1] if path else ""


def _unit_job(hit: dict, j: dict, msg: str, base: dict, host: str | None, o: Callable[[str], str]) -> TypedEvent:
    """A service manager's unit job message: which unit, which job (stop/start/...) and its phase (begun, done or
    another job result). The unit comes from the structured UNIT/USER_UNIT field, or from newer systemd's message
    that names it; the job from JOB_TYPE/JOB_RESULT, the catalog MESSAGE_ID, or that message's verb. A message
    that names no unit or no job (a description-only "Stopped ...", a resource summary) is not typed."""
    unit, scope, unit_origin = j.get("UNIT"), "system", o("UNIT")
    if not unit and j.get("USER_UNIT"):
        unit, scope, unit_origin = j["USER_UNIT"], "user", o("USER_UNIT")
    text = _UNIT_JOB_TEXT.match(msg)
    if not unit and text:
        unit, unit_origin = text.group("unit"), o("MESSAGE~systemd")
    job = phase = None
    if j.get("JOB_TYPE"):
        job, phase, job_origin = j["JOB_TYPE"], j.get("JOB_RESULT") or "begun", o("JOB_TYPE+JOB_RESULT")
    elif j.get("MESSAGE_ID") in _UNIT_JOB_IDS:
        (job, phase), job_origin = _UNIT_JOB_IDS[j["MESSAGE_ID"]], o("MESSAGE_ID")
    elif text and unit == text.group("unit"):
        (job, phase), job_origin = _UNIT_JOB_VERBS[text.group("verb")], o("MESSAGE~systemd")
    else:
        # The service manager's record of a unit's main process ending by signal or core dump (no job involved).
        exited = _UNIT_EXIT.match(msg)
        if unit and exited and exited.group("unit") == unit:
            job, phase = "exit", exited.group("code") or exited.group("result")
            job_origin = o("MESSAGE~systemd")
    if not unit or not job:
        raise Skip("systemd message is not a unit job record")
    fields = {**base,
              "service.unit": fv(unit, unit_origin), "service.name": fv(service_name(unit), unit_origin),
              "service.job": fv(job, job_origin), "service.job_phase": fv(phase, job_origin),
              "service.scope": fv(scope, unit_origin), "service.source": fv("journal", o("SYSLOG_IDENTIFIER"))}
    pid = j.get("_PID")
    if isinstance(pid, str) and pid.isdigit():
        fields["process.pid"] = fv(int(pid), o("_PID"))
    outcome = (Outcome.success if phase == "done" else Outcome.unknown if phase in {"begun", "skipped"}
               else Outcome.failure)
    ref = _ref(hit)
    return TypedEvent(id=event_id("service_change", [ref]), family="service_change", ts=_ts(hit["_source"]["@timestamp"]),
                      host=host, outcome=outcome, fields=fields, raw=[ref], normalizer=NORMALIZER_VERSION)


# ---------------------------------------------------------------------------------------------
# journald records as shippers index their fields (no JSON journal record)
# ---------------------------------------------------------------------------------------------

# Journal fields as the Filebeat journald input and Elastic Agent's Custom Journald integration index them: each
# journal field's indexed paths in preference order (releases 7.17-9.0 write syslog.*, 8.19 and 9.1+ log.syslog.*).
# Any other journal field is under journald.custom, lower case without its leading underscores.
JOURNAL_FIELD_PATHS = (
    ("MESSAGE", ("message",)),
    ("_BOOT_ID", ("journald.host.boot_id",)),
    ("_HOSTNAME", ("host.hostname",)),
    ("_COMM", ("journald.process.name",)),
    ("_EXE", ("journald.process.executable",)),
    ("_CMDLINE", ("journald.process.command_line",)),
    ("_PID", ("journald.pid", "process.pid")),
    ("_SYSTEMD_UNIT", ("systemd.unit",)),
    ("_SYSTEMD_USER_UNIT", ("systemd.user_unit",)),
    ("_TRANSPORT", ("systemd.transport",)),
    ("UNIT", ("journald.unit",)),
    ("SYSLOG_IDENTIFIER", ("syslog.identifier", "log.syslog.appname")),
    ("SYSLOG_PID", ("syslog.pid", "log.syslog.procid")),
    ("SYSLOG_FACILITY", ("syslog.facility", "log.syslog.facility.code")),
)
# The input drops _SOURCE_REALTIME_TIMESTAMP, so a journald copy of an audit record names no audit time: it cannot
# be paired with its audit record for the boot id (the audit record itself comes from the audit source).
JOURNAL_COPY_UNKEYED = "journald audit copy without source timestamp"


def _scalar_text(value) -> str | None:
    if isinstance(value, bool) or value is None or isinstance(value, (dict, list)):
        return None
    text = value if isinstance(value, str) else str(value)
    return text or None


def journal_from_fields(source: dict) -> tuple[dict, dict[str, str]]:
    """(journal record, indexed path of each journal field) from a journald document's ECS fields. journald's
    receive time (__REALTIME_TIMESTAMP) is @timestamp, which the input writes from it (milliseconds)."""
    j: dict[str, str] = {}
    paths: dict[str, str] = {}
    for key, candidates in JOURNAL_FIELD_PATHS:
        for path in candidates:
            text = _scalar_text(_get(source, path))
            if text is not None:
                j[key], paths[key] = text, path
                break
    custom = _get(source, "journald.custom")
    for name, value in (custom.items() if isinstance(custom, dict) else ()):
        key, text = str(name).upper(), _scalar_text(value)
        if text is not None and key not in j:
            j[key], paths[key] = text, f"journald.custom.{name}"
    when = _get(source, "@timestamp")
    if isinstance(when, str):
        try:
            j["__REALTIME_TIMESTAMP"] = str(_micros(datetime.fromisoformat(when)))
            paths["__REALTIME_TIMESTAMP"] = "@timestamp"
        except ValueError:
            pass
    return j, paths


def _indexed_origin(nid: str, paths: dict[str, str]) -> Callable[[str], str]:
    """The origin function of a record whose journal fields were read from indexed paths."""
    def origin(spec: str) -> str:
        parts = []
        for part in spec.split("+"):
            key, sep, suffix = part.partition("~")
            parts.append(paths.get(key, f"journald.custom.{key.lstrip('_').lower()}") + sep + suffix)
        return f"{nid}:" + "+".join(parts)
    return origin


def normalize_journal_fields(hit: dict, boots_seen: list | None = None) -> TypedEvent:
    """One journald record a shipper indexed as fields (Filebeat's journald input, Agent's Custom Journald)."""
    j, paths = journal_from_fields(hit["_source"])
    return _indexed_host(_journal_event(hit, j, _indexed_origin(hit["_id"], paths), boots_seen,
                                        copy_reason=JOURNAL_COPY_UNKEYED), hit)


# ---------------------------------------------------------------------------------------------
# linux.syslog: auth and syslog lines (System integration, Filebeat system module)
# ---------------------------------------------------------------------------------------------

SYSLOG_TIME_CAVEAT = "Time from a syslog line with no year or zone: the shipper supplied them."
SYSLOG_WRITER_CAVEAT = "Writer identity from the syslog header only."
SHIPPER_SSH_CAVEAT = "Parsed by the shipper; a user name containing ' from ' can move the recorded source address."
SHIPPER_PARSED_CAVEAT = "Parsed by the shipper; the line's text was not indexed."
# shadow-utils' own log lines (account names cannot hold a comma)
_USERADD = re.compile(r"^new user: name=(?P<name>[^,]+), UID=(?P<id>\d+), GID=(?P<gid>\d+)(?:, .*)?$")
_GROUPADD = re.compile(r"^new group: name=(?P<name>[^,]+), GID=(?P<id>\d+)$")
_SHIPPER_SSH = {"Accepted": (Outcome.success, "authentication", True),
                "Failed": (Outcome.failure, "authentication", None),
                "Invalid": (Outcome.failure, "user_lookup", False)}


def normalize_syslog(hit: dict) -> TypedEvent:
    """One auth or syslog line. With its message, the journal rules run on it (identifier: the syslog header's
    program); without it (the Filebeat system module drops the message when its own pattern matched), the fields
    the shipper parsed for sshd, sudo and useradd/groupadd are read, with a caveat saying so."""
    src, nid = hit["_source"], hit["_id"]
    ident = _get(src, "process.name")
    hostname = _get(src, "host.hostname")
    from_journal = _get(src, "input.type") == "journald"
    # a line read from the journal carries journald's own time and _COMM (the System integration's journald stream)
    caveats = [] if from_journal else [SYSLOG_TIME_CAVEAT]
    message = src.get("message")
    if isinstance(message, str) and message:
        j = {"SYSLOG_IDENTIFIER": ident, "MESSAGE": message}
        paths = {"SYSLOG_IDENTIFIER": "process.name", "MESSAGE": "message"}
        # the System integration's journald stream renames journald's _COMM, or the writer's own name, to
        # process.name: the writer is identified only when journald's captured name is still indexed
        comm = _get(src, "journald.process.name")
        if from_journal and isinstance(comm, str) and comm:
            j["_COMM"], paths["_COMM"] = comm, "journald.process.name"
        else:
            caveats.append(SYSLOG_WRITER_CAVEAT)
        if hostname:
            j["_HOSTNAME"], paths["_HOSTNAME"] = hostname, "host.hostname"
        if (pid := _scalar_text(_get(src, "process.pid"))) is not None:
            j["_PID"], paths["_PID"] = pid, "process.pid"
        if ident in ("useradd", "groupadd"):
            event = _syslog_account(hit, ident, message, hostname, f"{nid}:message~{ident}")
        else:
            event = _journal_event(hit, j, _indexed_origin(nid, paths), None, kind="syslog",
                                   copy_reason="syslog copy of an audit record (normalized from linux.audit)")
    else:
        event = _shipper_syslog(hit, ident, hostname)
    event.caveats.extend(caveat for caveat in caveats if caveat not in event.caveats)
    return _indexed_host(event, hit)


def _syslog_account(hit: dict, ident: str, message: str, host, origin: str) -> TypedEvent:
    rx, action = (_USERADD, "create_user") if ident == "useradd" else (_GROUPADD, "create_group")
    m = rx.match(message)
    if not m:
        raise Skip(f"{ident} line is not an account creation record")
    return _account_event(hit, host, action, m["name"], m["id"], origin, origin, [])


def _account_event(hit: dict, host, action: str, name, number, name_origin: str, id_origin: str,
                   caveats: list[str]) -> TypedEvent:
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    fields = {"account.action": fv(action, f"{nid}:process.name")}
    if name:
        fields["account.name"] = fv(str(name), name_origin)
    if number not in (None, ""):
        fields["account.id"] = fv(str(number), id_origin)
    pid = _get(src, "process.pid")
    if isinstance(pid, int) or isinstance(pid, str) and pid.isdigit():
        fields["process.pid"] = fv(int(pid), f"{nid}:process.pid")
    return TypedEvent(id=event_id("account_change", [ref]), family="account_change", ts=_ts(src["@timestamp"]),
                      host=host or _get(src, "host.name"), outcome=Outcome.success, fields=fields, raw=[ref],
                      normalizer=NORMALIZER_VERSION, caveats=list(caveats))


def _shipper_syslog(hit: dict, ident, hostname) -> TypedEvent:
    """The typed event of a syslog line whose message the shipper dropped, from the fields its pattern parsed."""
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    host = hostname or _get(src, "host.name")
    base = {"journal.identifier": fv(ident, f"{nid}:process.name"),
            "journal.unit": fv(None, f"{nid}:process.name")}
    ssh_event = _get(src, "system.auth.ssh.event")
    if ident == "sshd" and ssh_event in _SHIPPER_SSH:
        outcome, phase, valid = _SHIPPER_SSH[ssh_event]
        o = f"{nid}:system.auth.ssh.event"
        f = {**base, "auth.service": fv("sshd", f"{nid}:process.name"),
             "auth.method": fv(_get(src, "system.auth.ssh.method"), f"{nid}:system.auth.ssh.method"),
             "auth.phase": fv(phase, o)}
        if valid is not None:
            f["auth.user_valid"] = fv(valid, o)
        if _get(src, "source.ip"):
            f["source.ip"] = fv(_get(src, "source.ip"), f"{nid}:source.ip")
        if _get(src, "user.name"):
            f["user.name"] = fv(_get(src, "user.name"), f"{nid}:user.name")
        port = _get(src, "source.port")
        if isinstance(port, int) or isinstance(port, str) and port.isdigit():
            f["source.port"] = fv(int(port), f"{nid}:source.port")
        return TypedEvent(id=event_id("auth", [ref]), family="auth", ts=_ts(src["@timestamp"]), host=host,
                          outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION,
                          caveats=[SHIPPER_SSH_CAVEAT])
    sudo = _get(src, "system.auth.sudo")
    if ident == "sudo" and isinstance(sudo, dict) and sudo.get("command") is not None:
        o = f"{nid}:system.auth.sudo"
        f = {**base, "auth.service": fv("sudo", f"{nid}:process.name"),
             "user.name": fv(_get(src, "user.name"), f"{nid}:user.name"),
             "auth.target_user": fv(sudo.get("user"), f"{o}.user"),
             "sudo.command": fv(sudo.get("command"), f"{o}.command"),
             "process.cwd": fv(sudo.get("pwd"), f"{o}.pwd")}
        outcome = Outcome.failure if sudo.get("error") else Outcome.success
        return TypedEvent(id=event_id("privilege_use", [ref]), family="privilege_use", ts=_ts(src["@timestamp"]),
                          host=host, outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION,
                          caveats=[SHIPPER_PARSED_CAVEAT])
    if ident == "useradd" and (_get(src, "user.target.name") or _get(src, "user.name")):
        prefix = "user.target" if _get(src, "user.target.name") else "user"
        return _account_event(hit, host, "create_user", _get(src, f"{prefix}.name"), _get(src, f"{prefix}.id"),
                              f"{nid}:{prefix}.name", f"{nid}:{prefix}.id", [SHIPPER_PARSED_CAVEAT])
    if ident == "groupadd" and _get(src, "group.name"):
        return _account_event(hit, host, "create_group", _get(src, "group.name"), _get(src, "group.id"),
                              f"{nid}:group.name", f"{nid}:group.id", [SHIPPER_PARSED_CAVEAT])
    raise Skip(f"syslog identifier {ident!r} is not normalized")


# ---------------------------------------------------------------------------------------------
# Auditbeat / Auditd Manager: one document per audit event, records merged by the shipper
# ---------------------------------------------------------------------------------------------

# event.action (go-libaudit's normalization) -> the family the event is expected to give. The document's records are
# rebuilt from its fields and normalized exactly as raw records of one event are; an action outside this table gives
# whatever its records give (a process_observed view of its SYSCALL), else it is counted as not normalized.
AUDITBEAT_ACTIONS = {
    "executed": "process_exec",
    "connected-to": "net_socket", "accepted-connection-from": "net_socket",
    "opened-file": "file_change", "changed-file-attributes-of": "file_change",
    "changed-file-permissions-of": "file_change", "changed-file-ownership-of": "file_change",
    "changed-timestamp-of": "file_change", "renamed": "file_change", "deleted": "file_change",
    "created-directory": "file_change", "created-file": "file_change", "linked": "file_change",
    "loaded-kernel-module": "kernel_module", "unloaded-kernel-module": "kernel_module",
    "logged-in": "auth", "started-session": "auth",
    "added-user-account": "account_change", "modified-user-account": "account_change",
    "changed-password": "account_change", "added-group-account-to": "account_change",
    "deleted-user-account": "account_change", "modified-group-account": "account_change",
    "deleted-group-account-from": "account_change", "changed-group": "account_change",
    "locked-account": "account_change", "unlocked-account": "account_change",
    "started-service": "service_change", "stopped-service": "service_change",
    "changed-audit-configuration": "audit_config",
    "booted-system": "system_state", "shutdown-system": "system_state", "changed-to-runlevel": "system_state",
}
_AUDITBEAT_RESULTS = {"success": "success", "fail": "failed", "failed": "failed", "failure": "failed"}
_UNSET = {"unset", "4294967295", "-1"}
# Tags a shipper adds that are not audit rule keys.
_SHIPPER_TAGS = frozenset({"preserve_original_event", "forwarded", "beats_input_codec_plain_applied",
                           "beats_input_raw_event", "_grokparsefailure", "_jsonparsefailure"})


def auditbeat_lines(source: dict) -> list[str]:
    """The raw audit lines an Auditbeat (event.original array) or Auditd Manager (one newline-joined string)
    document carries, or [] when it carries none."""
    original = _get(source, "event.original")
    lines = original if isinstance(original, list) else (original.split("\n") if isinstance(original, str) else [])
    return [line for line in lines if isinstance(line, str) and line.strip()]


def _sockaddr_hex(family, address, port) -> str | None:
    """The shipper's parsed socket address in the hex form auditd logs it (what parse_sockaddr reads)."""
    try:
        number = int(port) if port not in (None, "") else 0
        if family in ("ipv4", "inet"):
            return (b"\x02\x00" + number.to_bytes(2, "big") + ipaddress.IPv4Address(address).packed
                    + bytes(8)).hex()
        if family in ("ipv6", "inet6"):
            return (b"\x0a\x00" + number.to_bytes(2, "big") + bytes(4) + ipaddress.IPv6Address(address).packed
                    + bytes(4)).hex()
    except (ValueError, TypeError, OverflowError):
        return None
    if family in ("unix", "local"):
        return "0100"
    return None


def auditbeat_records(hit: dict) -> list[tuple[dict, AuditRecord]]:
    """The audit records of one Auditbeat event document, rebuilt from its fields: the event's main record (its
    message type), and the PATH, CWD, EXECVE, SOCKADDR and KERN_MODULE records whose content the shipper merged
    into it. Each record names the indexed path of each key."""
    src = hit["_source"]
    message_type = _get(src, "auditd.message_type")
    if not isinstance(message_type, str) or not re.fullmatch(r"[a-z_]+", message_type):
        raise AuditParseError("Auditbeat event without a message type")
    sequence = _scalar_text(_get(src, "auditd.sequence"))
    if sequence is None or not sequence.isdigit():
        raise AuditParseError("Auditbeat event without a sequence number")
    when = _get(src, "@timestamp")
    if not isinstance(when, str):
        raise AuditParseError("Auditbeat event without @timestamp")
    ts, serial = round(datetime.fromisoformat(when).timestamp(), 3), int(sequence)
    data = _get(src, "auditd.data") if isinstance(_get(src, "auditd.data"), dict) else {}
    action = _get(src, "event.action")

    def record(kind: str, pairs: dict[str, tuple[object, str]], enriched: dict[str, str] | None = None
               ) -> AuditRecord:
        fields, origins = {}, {}
        for key, (value, path) in pairs.items():
            text = _scalar_text(value)
            if text is not None:
                fields[key], origins[key] = text, path
        return AuditRecord(type=kind, ts=ts, serial=serial, fields=fields,
                           raw_fields={key: (value, True) for key, value in fields.items()},
                           enriched=enriched or {}, origins=origins)

    main_type = message_type.upper()
    pairs: dict[str, tuple[object, str]] = {
        key: (value, f"auditd.data.{key}") for key, value in data.items() if key not in ("socket", "arch", "syscall")}
    arch_name = data.get("arch")
    # go-libaudit names the arch; an arch without a token here stays named (its calls are then not decoded)
    arch = AGENT_ARCH_TOKENS.get(arch_name.lower(), arch_name) if isinstance(arch_name, str) and arch_name else None
    if arch is not None:
        pairs["arch"] = (arch, "auditd.data.arch")
    call = data.get("syscall")
    if isinstance(call, str) and call:
        pairs["syscall"] = (call if call.isdigit() else (syscall_number(call, arch or "") or call),
                            "auditd.data.syscall")
    result = _get(src, "auditd.result")
    if isinstance(result, str) and result.lower() in _AUDITBEAT_RESULTS:
        if main_type == "SYSCALL":
            pairs["success"] = ("yes" if result.lower() == "success" else "no", "auditd.result")
        else:
            pairs["res"] = (_AUDITBEAT_RESULTS[result.lower()], "auditd.result")
    # For a user-space record go-libaudit fills user.* with the audit uid and user.effective.* (or user.target.*,
    # group.*) with the account the record is about, as the Auditd Logs pipeline's copies do (AGENT_COPY_TYPES): the
    # record's uid is user.effective only where that comes from uid alone, and otherwise is not recorded.
    user_space = main_type in AGENT_COPY_TYPES
    identities = ((("uid", "user.effective.id"),) if main_type in COPY_UID_EFFECTIVE_TYPES else ()) if user_space \
        else (("uid", "user.id"), ("euid", "user.effective.id"), ("suid", "user.saved.id"),
              ("fsuid", "user.filesystem.id"), ("gid", "user.group.id"), ("egid", "user.effective.group.id"))
    for key, path in (("pid", "process.pid"), ("ppid", "process.parent.pid"), ("exe", "process.executable"),
                      ("comm", "process.name"), *identities, ("addr", "source.ip")):
        value = _get(src, path)
        if value is not None and key not in pairs and not (key == "addr" and main_type == "SYSCALL"):
            pairs[key] = (value, path)
    for key, path in (("auid", "user.audit.id"), ("ses", "auditd.session")):
        value = _scalar_text(_get(src, path))
        if value is not None and key not in pairs:
            pairs[key] = ("4294967295" if value == "unset" else value, path)
    keys = [tag for tag in (_get(src, "tags") or []) if isinstance(tag, str) and tag not in _SHIPPER_TAGS]
    if keys and main_type == "SYSCALL":
        pairs["key"] = ("\x01".join(keys), "tags")
    names = ((("UID", "user.effective.name"),) if main_type in COPY_UID_EFFECTIVE_TYPES else ()) if user_space \
        else (("UID", "user.name"), ("EUID", "user.effective.name"))
    enriched = {name: str(_get(src, path)) for name, path in (*names, ("AUID", "user.audit.name"))
                if _scalar_text(_get(src, path)) is not None}
    if main_type == "SYSCALL" and arch is None:
        raise AuditParseError("Auditbeat SYSCALL event without an architecture: its call cannot be read")
    records = [record(main_type, pairs, enriched)]
    paths = _get(src, "auditd.paths")
    for item in paths if isinstance(paths, list) else []:
        if isinstance(item, dict):
            records.append(record("PATH", {key: (value, f"auditd.paths.{key}") for key, value in item.items()}))
    if (cwd := _get(src, "process.working_directory")) is not None:
        records.append(record("CWD", {"cwd": (cwd, "process.working_directory")}))
    if action == "executed" or main_type == "EXECVE":
        args = _get(src, "process.args")
        if isinstance(args, list) and all(isinstance(arg, str) for arg in args):
            argv = {f"a{index}": (arg, "process.args") for index, arg in enumerate(args)}
            count = data.get("argc", len(args))
            records.append(record("EXECVE", {"argc": (count, "auditd.data.argc" if "argc" in data
                                                      else "process.args"), **argv}))
    socket = data.get("socket") if isinstance(data.get("socket"), dict) else None
    if socket is not None and (saddr := _sockaddr_hex(socket.get("family"), socket.get("addr"),
                                                      socket.get("port"))) is not None:
        records.append(record("SOCKADDR", {"saddr": (saddr, "auditd.data.socket")}))
    if action in ("loaded-kernel-module", "unloaded-kernel-module") and data.get("name"):
        records.append(record("KERN_MODULE", {"name": (data["name"], "auditd.data.name")}))
    return [(hit, item) for item in records]


# ---------------------------------------------------------------------------------------------
# apache
# ---------------------------------------------------------------------------------------------

APACHE_ZONE_CAVEAT = "Zone from the shipper's locale"


def normalize_apache_access(hit: dict, *, parsed_fields=None, line_origin=None) -> TypedEvent:
    """One access-log line. A client logged by host name (the shipper's source.domain) has no source.ip: the event
    is kept without it, and rules that need it count it as missing."""
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    f = {}
    for typed, native in (("source.ip", "source.ip"), ("http.request.method", "http.request.method"),
                          ("http.response.status_code", "http.response.status_code"),
                          ("url.original", "url.original"), ("user_agent.original", "user_agent.original")):
        v = _get(src, native)
        if v is not None:
            f[typed] = fv(v, f"{nid}:{native}")
    if parsed_fields is not None:
        f = {key: fv(value, line_origin) for key, value in parsed_fields.items()}
    status = f.get("http.response.status_code")
    outcome = Outcome.unknown if status is None else (Outcome.success if int(status.value) < 400 else Outcome.failure)
    return TypedEvent(id=event_id("http_access", [ref]), family="http_access", ts=_ts(src["@timestamp"]),
                      host=_get(src, "host.name"), outcome=outcome, fields=f, raw=[ref], normalizer=NORMALIZER_VERSION)


def normalize_apache_error(hit: dict) -> TypedEvent:
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    f = {"web.error_message": fv(src.get("message"), f"{nid}:message")}
    if _get(src, "source.ip"):
        f["source.ip"] = fv(_get(src, "source.ip"), f"{nid}:source.ip")
    zone = _get(src, "event.timezone")
    # an error-log line names no zone: the importer assumed UTC, a shipper used its own locale's zone
    caveats = (["timestamp timezone assumed UTC by importer"] if zone == "assumed_utc"
               else [APACHE_ZONE_CAVEAT] if zone not in (None, "") else [])
    return TypedEvent(id=event_id("web_error", [ref]), family="web_error", ts=_ts(src["@timestamp"]),
                      host=_get(src, "host.name"), fields=f, raw=[ref], normalizer=NORMALIZER_VERSION, caveats=caveats)


# ---------------------------------------------------------------------------------------------
# suricata EVE (authoritative JSON in event.original)
# ---------------------------------------------------------------------------------------------
#
# Handshake and DNS fields shared by the Suricata and Arkime paths, so rules read one contract:
# - tls.ja3, tls.ja3s, tls.ja4, ssh.hassh, ssh.hassh_server: list[str], sorted and distinct, every value the record
#   carries (Arkime stores them as arrays; Suricata logs one per transaction). JA3, JA3S and HASSH are hex
#   digests and are lowercased; JA4 is kept as recorded.
# - tls.version: list[str] spelled as Arkime does ("TLSv1.2"). tls.client.server_name: str (Suricata SNI).
#   tls.resumed: bool (Suricata: the handshake resumed a session, so no certificate was sent).
# - tls.server.certificates: list[dict], one per distinct presented certificate, sorted by (sha1, subject,
#   not_before) because Arkime's array is not in chain order. Keys: subject_cn, subject_on, issuer_cn, issuer_on,
#   alt_names (list[str]); subject_dn, issuer_dn (str or None, Suricata only); not_before, not_after (ISO-8601
#   UTC or None); valid_days (int or None, as Arkime reported it); sha1, serial (lowercase hex or None);
#   names_compared ("distinguished name" or "CN and O"); self_issued (bool, or None when either name is empty:
#   the subject name equals the issuer name); issues_other (bool: its subject name is the issuer name of another
#   certificate in the same record, so it is a CA in the presented chain, not the server's own certificate).
# - tls.server.subject_cn, tls.server.issuer_cn (list[str]), tls.server.not_before, tls.server.not_after (ISO),
#   tls.server.hash_sha1 (str): the server's own certificate, set only when exactly one presented certificate
#   issues no other (Suricata logs only the server's certificate). Never a pick among several.
# - ssh.client.software, ssh.client.proto_version, ssh.server.software, ssh.server.proto_version: str (Suricata,
#   attributed by direction). ssh.version (Arkime): list[str] of SSH banners, not attributed to either side.
# - dns.question.names, dns.question.types, dns.response_codes: sorted distinct list[str]. dns.question.name,
#   dns.question.type, dns.response_code: str, only when the record holds exactly one distinct value.
#   dns.version: non-negative int when Suricata records one; dns.id: int or str as recorded.
#   dns.answers, dns.authorities: list of {"name", "type", "ttl", "data"} in record order.
# - parse.malformed: sorted native paths that were present but not of the documented type. Such a value is
#   dropped, never guessed or stringified; a rule that needs it counts the record as missing that field.

_HEX_DIGESTS = {"tls.ja3", "tls.ja3s", "ssh.hassh", "ssh.hassh_server"}
# Suricata writes RFC 4514-style one-line names ("C=US, O=Example, CN=host"): romulus.evidence.certificates splits
# them, so a comma inside a value ("O=Acme, Inc.") does not split.
_SURICATA_TLS_VERSION = re.compile(r"^TLS (\d\.\d)$")


def _absent(value) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _strings(value, path: str, bad: list[str], *, lower: bool = False) -> list[str] | None:
    """A string-or-array-of-strings field as a sorted distinct list (Elasticsearch stores `x` and `[x]` alike).
    None when absent; any non-string element makes the whole field malformed."""
    if _absent(value):
        return None
    items = value if isinstance(value, list) else [value]
    if not all(isinstance(item, str) for item in items):
        bad.append(path)
        return None
    out = sorted({item.lower() if lower else item for item in items if item})
    return out or None


def _scalar_str(value, path: str, bad: list[str]) -> str | None:
    if _absent(value):
        return None
    if not isinstance(value, str):
        bad.append(path)
        return None
    return value


def _objects(value, path: str, bad: list[str]) -> list[dict] | None:
    """An object-or-array-of-objects block as a list. None when absent; a non-object element is malformed."""
    if _absent(value):
        return None
    items = value if isinstance(value, list) else [value]
    if not all(isinstance(item, dict) for item in items):
        bad.append(path)
        return None
    return items


def _count(value, path: str, bad: list[str]) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        bad.append(path)
        return None
    return value


def _icmp_number(value, path: str, bad: list[str]) -> int | None:
    """An ICMP type or code: an unsigned byte, without string/bool coercion."""
    number = _count(value, path, bad)
    if number is not None and number > 255:
        bad.append(path)
        return None
    return number


def _icmp_value(value, path: str, bad: list[str]) -> int | list[int] | None:
    """An Arkime ICMP type/code field: one byte or its INT_GHASH multi-value representation."""
    if not isinstance(value, list):
        return _icmp_number(value, path, bad)
    if not value:
        return None
    local_bad: list[str] = []
    numbers = [_icmp_number(item, path, local_bad) for item in value]
    if local_bad or any(number is None for number in numbers):
        bad.append(path)
        return None
    return sorted(set(numbers))


def _cert_time(value, path: str, bad: list[str]) -> str | None:
    """A certificate validity bound as ISO-8601 UTC. Arkime stores epoch milliseconds; Suricata writes ISO time
    without a zone, in UTC."""
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            return datetime.fromtimestamp(value / 1000, UTC).isoformat()
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value)
            return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
    except (ValueError, OverflowError, OSError):
        pass
    bad.append(path)
    return None


def _hex_id(value, path: str, bad: list[str]) -> str | None:
    """A certificate hash or serial as lowercase hex; separators are kept for hashes, removed for serials."""
    text = _scalar_str(value, path, bad)
    return None if text is None else text.lower()


def _suricata_tls(t: dict, o: str, bad: list[str], caveats: list[str]) -> dict:
    f = {}
    sni = _scalar_str(t.get("sni"), "tls.sni", bad)
    if sni is not None:
        f["tls.client.server_name"] = fv(sni, f"{o}.tls.sni")
    version = _scalar_str(t.get("version"), "tls.version", bad)
    if version is not None:
        m = _SURICATA_TLS_VERSION.match(version)
        f["tls.version"] = fv([f"TLSv{m.group(1)}" if m else version], f"{o}.tls.version")
    for typed, key in (("tls.ja3", "ja3"), ("tls.ja3s", "ja3s")):
        value, path = t.get(key), f"tls.{key}"
        if isinstance(value, dict):                     # {"hash": ..., "string": ...}
            value, path = value.get("hash"), f"tls.{key}.hash"
        hashes = _strings(value, path, bad, lower=True)
        if hashes:
            f[typed] = fv(hashes, f"{o}.{path}")
    ja4 = _strings(t.get("ja4"), "tls.ja4", bad)
    if ja4:
        f["tls.ja4"] = fv(ja4, f"{o}.tls.ja4")
    if isinstance(t.get("session_resumed"), bool):
        f["tls.resumed"] = fv(t["session_resumed"], f"{o}.tls.session_resumed")
    cert_keys = ("subject", "issuerdn", "notbefore", "notafter", "fingerprint", "serial")
    if any(not _absent(t.get(k)) for k in cert_keys):
        subject = _scalar_str(t.get("subject"), "tls.subject", bad)
        issuer = _scalar_str(t.get("issuerdn"), "tls.issuerdn", bad)
        sparts, iparts = _dn_parts(subject or ""), _dn_parts(issuer or "")
        serial = _hex_id(t.get("serial"), "tls.serial", bad)
        cert = {"subject_cn": [v for k, v in sparts if k == "CN"], "subject_on": [v for k, v in sparts if k == "O"],
                "issuer_cn": [v for k, v in iparts if k == "CN"], "issuer_on": [v for k, v in iparts if k == "O"],
                "subject_dn": subject, "issuer_dn": issuer,
                "not_before": _cert_time(t.get("notbefore"), "tls.notbefore", bad),
                "not_after": _cert_time(t.get("notafter"), "tls.notafter", bad), "valid_days": None,
                "alt_names": _strings(t.get("subjectaltname"), "tls.subjectaltname", bad) or [],
                "sha1": _hex_id(t.get("fingerprint"), "tls.fingerprint", bad),
                "serial": serial.replace(":", "") if serial else None}
        f.update(_certificate_fields([cert], f"{o}.tls.{'+'.join(cert_keys)}", caveats))
    return f


def _suricata_ssh(s: dict, o: str, bad: list[str]) -> dict:
    f = {}
    for side, typed_hassh in (("client", "ssh.hassh"), ("server", "ssh.hassh_server")):
        block = s.get(side)
        if _absent(block):
            continue
        if not isinstance(block, dict):
            bad.append(f"ssh.{side}")
            continue
        for typed, key in (("software", "software_version"), ("proto_version", "proto_version")):
            value = _scalar_str(block.get(key), f"ssh.{side}.{key}", bad)
            if value is not None:
                f[f"ssh.{side}.{typed}"] = fv(value, f"{o}.ssh.{side}.{key}")
        hassh = block.get("hassh")
        value, path = (hassh.get("hash"), f"ssh.{side}.hassh.hash") if isinstance(hassh, dict) \
            else (hassh, f"ssh.{side}.hassh")
        hashes = _strings(value, path, bad, lower=True)
        if hashes:
            f[typed_hassh] = fv(hashes, f"{o}.{path}")
    return f


def _dns_record(item: dict, path: str, bad: list[str]) -> dict:
    ttl = _count(item.get("ttl"), f"{path}.ttl", bad)
    return {"name": _scalar_str(item.get("rrname"), f"{path}.rrname", bad),
            "type": _scalar_str(item.get("rrtype"), f"{path}.rrtype", bad), "ttl": ttl,
            "data": item["rdata"] if isinstance(item.get("rdata"), str) else None}


def _dns_name_fields(names: set[str], types: set[str], codes: set[str], origin: str) -> dict:
    """List fields always; the scalar only when exactly one distinct value exists."""
    f = {}
    for values, plural, single in ((names, "dns.question.names", "dns.question.name"),
                                   (types, "dns.question.types", "dns.question.type"),
                                   (codes, "dns.response_codes", "dns.response_code")):
        if values:
            f[plural] = fv(sorted(values), origin)
            if len(values) == 1:
                f[single] = fv(next(iter(values)), origin)
    return f


def _suricata_dns(d: dict, o: str, bad: list[str]) -> dict:
    """EVE DNS in its three layouts. Query records (every version) and v2 answer records carry the question in
    the top-level rrname/rrtype; v3 records carry it in `queries`. A v1 answer record (no `version`) is one
    resource record of the response: its rrname/rrtype/ttl/rdata describe that answer (a CNAME target, say), so
    they are typed as an answer and never as the question."""
    f = {"dns.type": fv(d.get("type"), f"{o}.dns.type")}
    version = _count(d.get("version"), "dns.version", bad)
    if version is not None:
        f["dns.version"] = fv(version, f"{o}.dns.version")
    ident = d.get("id")
    if isinstance(ident, (int, str)) and not isinstance(ident, bool):
        f["dns.id"] = fv(ident, f"{o}.dns.id")
    elif ident is not None:
        bad.append("dns.id")
    names, types = set(), set()
    if d.get("type") == "answer" and d.get("version") is None:
        answer = _dns_record(d, "dns", bad)
        if any(v is not None for v in answer.values()):
            f["dns.answers"] = fv([answer], f"{o}.dns.rrname+rrtype+ttl+rdata")
        rrname = rrtype = None
    else:
        rrname = _scalar_str(d.get("rrname"), "dns.rrname", bad)
        rrtype = _scalar_str(d.get("rrtype"), "dns.rrtype", bad)
    names.update([rrname] if rrname else [])
    types.update([rrtype] if rrtype else [])
    queries = _objects(d.get("queries"), "dns.queries", bad) or []
    for i, query in enumerate(queries):
        q = _dns_record(query, f"dns.queries[{i}]", bad)
        names.update([q["name"]] if q["name"] else [])
        types.update([q["type"]] if q["type"] else [])
    code = _scalar_str(d.get("rcode"), "dns.rcode", bad)
    f.update(_dns_name_fields(names, types, {code} if code else set(), f"{o}.dns.rrname+rrtype+queries+rcode"))
    for typed, key in (("dns.answers", "answers"), ("dns.authorities", "authorities")):
        items = _objects(d.get(key), f"dns.{key}", bad)
        if items and typed not in f:
            f[typed] = fv([_dns_record(item, f"dns.{key}[{i}]", bad) for i, item in enumerate(items)],
                          f"{o}.dns.{key}")
    grouped = d.get("grouped")
    if "dns.answers" not in f and not _absent(grouped):
        if not isinstance(grouped, dict) or not all(isinstance(v, list) for v in grouped.values()):
            bad.append("dns.grouped")
        else:
            f["dns.answers"] = fv([{"name": None, "type": rtype, "ttl": None,
                                    "data": value if isinstance(value, str) else None}
                                   for rtype, values in sorted(grouped.items()) for value in values],
                                  f"{o}.dns.grouped")
    return f


def _app_block(eve: dict, key: str) -> dict | None:
    """An app-layer block of a Suricata record; a block of the wrong type makes the record unreadable."""
    if key not in eve:
        return None
    block = eve[key]
    if not isinstance(block, dict):
        raise TypeError(f"suricata {key} block is {type(block).__name__}, not an object")
    return block


def _suricata_community_id(eve: dict, o: str):
    """The record's community id: as Suricata wrote it, or, when its sensor did not write one (the setting is per
    sensor and output), computed from the record's own 5-tuple, with an origin that says so. The computed id equals
    the written one, so records of one connection from different sensors and event types share it."""
    written = eve.get("community_id")
    if written not in (None, ""):
        return fv(written, f"{o}.community_id")
    computed = community_id(eve.get("src_ip"), eve.get("src_port"), eve.get("dest_ip"), eve.get("dest_port"),
                            eve.get("proto"))
    return fv(computed, f"{o}.src_ip+src_port+dest_ip+dest_port+proto#computed:community_id_v1")


def normalize_suricata(hit: dict) -> TypedEvent:
    src, nid = hit["_source"], hit["_id"]
    if is_elastic_suricata(src):
        # Filebeat or the Agent indexed the parsed record without its EVE line
        return normalize_elastic_suricata(hit)
    try:
        eve = json.loads(_get(src, "event.original") or src.get("message") or "")
    except json.JSONDecodeError as e:
        raise ValueError(f"suricata event.original is not JSON: {e}") from e
    return _suricata_event(hit, eve, f"{nid}:event.original#eve")


def _suricata_event(hit: dict, eve: dict, o: str, *, origins: dict[str, str] | None = None,
                    caveats: list[str] | None = None, malformed: list[str] | None = None,
                    host: str | None = None) -> TypedEvent:
    """The typed event of one EVE record. `o` prefixes every origin (the EVE record's own location); `origins`
    replaces the origin of typed fields whose value was read from somewhere else, and `caveats` and `malformed`
    are what the caller already found."""
    src, ref = hit["_source"], _ref(hit)
    et = eve.get("event_type")
    f = {"source.ip": fv(eve.get("src_ip"), f"{o}.src_ip"), "destination.ip": fv(eve.get("dest_ip"), f"{o}.dest_ip"),
         "source.port": fv(eve.get("src_port"), f"{o}.src_port"),
         "destination.port": fv(eve.get("dest_port"), f"{o}.dest_port"),
         "network.transport": fv((eve.get("proto") or "").lower() or None, f"{o}.proto"),
         "network.app_proto": fv(eve.get("app_proto"), f"{o}.app_proto"),
         "network.community_id": _suricata_community_id(eve, o),
         "suricata.flow_id": fv(eve.get("flow_id"), f"{o}.flow_id")}
    family = {"alert": "net_alert", "flow": "net_flow", "netflow": "net_flow", "dns": "dns_query",
              "http": "http_tx", "fileinfo": "file_transfer", "tls": "tls_session", "ssh": "ssh_session"}.get(et)
    if family is None:
        raise Skip(f"suricata event_type {et!r} is not normalized")
    if et == "alert":
        a = eve.get("alert", {})
        for k in ("signature", "signature_id", "category", "severity", "action"):
            f[f"alert.{k}"] = fv(a.get(k), f"{o}.alert.{k}")
        md = a.get("metadata") or {}
        f["alert.mitre_technique_id"] = fv(md.get("mitre_technique_id"), f"{o}.alert.metadata.mitre_technique_id")
        f["alert.signature_severity"] = fv(md.get("signature_severity"), f"{o}.alert.metadata.signature_severity")
    flow = eve.get("flow") or eve.get("netflow") or {}
    for k in ("bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient", "bytes", "pkts", "start", "end",
              "state"):
        if k in flow:
            f[f"flow.{k}"] = fv(flow[k], f"{o}.flow.{k}")
    bad: list[str] = list(malformed or [])
    for typed, native in (("icmp.type", "icmp_type"), ("icmp.code", "icmp_code")):
        number = _icmp_number(eve.get(native), typed, bad)
        if number is not None:
            f[typed] = fv(number, f"{o}.{native}")
    tcp = _app_block(eve, "tcp")
    if tcp is not None:
        syn = tcp.get("syn")
        if syn is not None:
            if isinstance(syn, bool):
                f["tcp.syn"] = fv(syn, f"{o}.tcp.syn")
            else:
                bad.append("tcp.syn")
        for name in ("tcp_flags_ts", "tcp_flags_tc", "state"):
            value = _scalar_str(tcp.get(name), f"tcp.{name}", bad)
            if value is not None:
                f[f"tcp.{name}"] = fv(value, f"{o}.tcp.{name}")
    caveats = list(caveats or [])
    d = _app_block(eve, "dns")
    if d is not None:
        f.update(_suricata_dns(d, o, bad))
    t = _app_block(eve, "tls")
    if t is not None:
        f.update(_suricata_tls(t, o, bad, caveats))
    s = _app_block(eve, "ssh")
    if s is not None:
        f.update(_suricata_ssh(s, o, bad))
    if bad:
        f["parse.malformed"] = fv(sorted(set(bad)), f"{o}#malformed")
    if "http" in eve:
        h = eve["http"]
        for typed, k in (("http.hostname", "hostname"), ("url.original", "url"),
                         ("user_agent.original", "http_user_agent"), ("http.request.method", "http_method"),
                         ("http.response.status_code", "status"), ("http.response.length", "length"),
                         ("http.content_type", "http_content_type")):
            if k in h:
                f[typed] = fv(h[k], f"{o}.http.{k}")
    if "fileinfo" in eve:
        fi = eve["fileinfo"]
        f["file.name"] = fv(fi.get("filename"), f"{o}.fileinfo.filename")
        f["file.size"] = fv(fi.get("size"), f"{o}.fileinfo.size")
    ts = _ts(eve["timestamp"]) if eve.get("timestamp") else _ts(src["@timestamp"])
    fields = {k: v for k, v in f.items() if v.value is not None}
    for name, origin in (origins or {}).items():
        if name in fields:
            fields[name] = fv(fields[name].value, origin)
    return TypedEvent(id=event_id(family, [ref]), family=family, ts=ts,
                      host=_get(src, "host.name") if host is None else host,
                      fields=fields, raw=[ref], normalizer=NORMALIZER_VERSION, caveats=caveats)


# ---------------------------------------------------------------------------------------------
# Suricata EVE as Malcolm indexes it
# ---------------------------------------------------------------------------------------------
# Malcolm (cisagov/Malcolm, Apache-2.0) parses each EVE line in Logstash and indexes the parsed record without the
# line: logstash/pipelines/suricata/11_suricata_logs.conf parses `message` into `suricata.*`, and
# logstash/pipelines/enrichment/98_finalize.conf removes `message`; `event.original` is never written. The layout
# read here (as of commit c6160d8e3101c017a45df9d40504ece3da047f43):
# - event.provider is "suricata"; event.dataset is the bare event_type ("alert", "flow", ...).
# - Moved: src_ip, dest_ip, src_port, dest_port to source.ip, destination.ip, source.port, destination.port;
#   proto to network.transport (lowercased); community_id to network.community_id; alert.signature and
#   alert.signature_id to rule.name and rule.id; tls.version to tls.version; tls.ja3.hash, tls.ja3s.hash and
#   tls.ja4.hash to tls.client.ja3, tls.server.ja3s and tls.client.ja4.
# - rule.category starts with alert.category (or, without one, alert.metadata.former_category); a MITRE tactic
#   name, technique name or framework may follow. alert.metadata.mitre_technique_id becomes threat.technique.id
#   (the parent ids) and threat.technique.subtechnique.id (the dotted ids).
# - network.protocol starts with app_proto, then app_proto_orig/_expected/_tc/_ts and anomaly.app_proto; while it
#   is still empty, names inferred from the app-layer blocks present (and "icmp" from ICMP fields), else
#   tls.from_proto, are put in it; tunnel.proto is appended. enrichment/96_make_unique.conf then removes duplicates
#   (first occurrences kept), removes "failed", and renames dcerpc, ftp-data and krb5 to dce_rpc, ftp and krb.
# - Everything else the EVE normalizer reads stays under suricata.* (flow_id, timestamp, flow, netflow, tcp, dns,
#   http, fileinfo, ssh, tls, icmp_type, icmp_code, alert.severity, alert.action, alert.metadata); timestamp,
#   flow.start/end and tls.notbefore/notafter are rewritten as ISO-8601 times by 13_suricata_convert.conf, to the
#   millisecond: finer EVE precision does not survive, so these times can differ from the EVE line's below 1 ms.
# - A record whose app_proto_ts or app_proto_tc is "failed" loses suricata.http and suricata.tls (and suricata.dns
#   when app_proto_ts is), tagged proto_parse_failed; a record with no timestamp is given the ingest time, tagged
#   _missing_timestamp.

MALCOLM_NO_APP_PROTO_CAVEAT = (
    "Malcolm removes the value 'failed' from network.protocol: no application protocol on this record means "
    "Suricata identified none or reported its protocol detection 'failed'")
MALCOLM_FTP_CAVEAT = (
    "Malcolm writes Suricata's ftp and ftp-data both as 'ftp': the record does not say which of the two Suricata "
    "identified, so both are typed as candidates (network.app_proto_candidates)")
# The protocols Malcolm's "ftp" stands for on a Suricata record.
MALCOLM_FTP_CANDIDATES = ["ftp", "ftp-data"]
MALCOLM_PARSE_FAILED_CAVEAT = (
    "Malcolm drops the http and tls blocks (and the dns block, when the client side failed) of a record whose "
    "protocol parsing failed: fields from them are not typed")
MALCOLM_MISSING_TIMESTAMP_CAVEAT = (
    "Malcolm found no Suricata timestamp on this record and gave it the time Malcolm ingested it")
# Malcolm's renames that each name a single Suricata protocol, reversed. "ftp" stands for ftp or ftp-data.
_MALCOLM_PROTOCOL_ORIGINAL = {"dce_rpc": "dcerpc", "krb": "krb5"}
_MALCOLM_PROTOCOL_RENAMED = {"dcerpc": "dce_rpc", "ftp-data": "ftp", "krb5": "krb"}
# EVE event types that carry app_proto once Suricata identified a protocol (Suricata's EVE format documentation:
# "When an application layer protocol event is detected, the common section will have an app_proto field"; its
# http, dns, tls and ssh records carry none).
_EVE_APP_PROTO_TYPES = frozenset({"alert", "flow", "netflow", "fileinfo"})
# What Malcolm adds to network.protocol after app_proto. Suricata writes the app_proto_* fields only when they
# differ from app_proto, so a first value found among these means the record had no app_proto.
_MALCOLM_AFTER_APP_PROTO = ("app_proto_orig", "app_proto_expected", "app_proto_tc", "app_proto_ts", "anomaly.app_proto",
                            "tls.from_proto", "tunnel.proto")
_MALCOLM_MOVED = (("src_ip", "source.ip", "source.ip"), ("dest_ip", "destination.ip", "destination.ip"),
                  ("src_port", "source.port", "source.port"), ("dest_port", "destination.port", "destination.port"),
                  ("proto", "network.transport", "network.transport"))
_MALCOLM_MOVED_TLS = (("version", "tls.version"), ("ja3", "tls.client.ja3"), ("ja3s", "tls.server.ja3s"),
                      ("ja4", "tls.client.ja4"))


def is_malcolm_suricata(src: dict) -> bool:
    """A Suricata record as Malcolm indexes it: provider "suricata" and the bare EVE event type as the dataset
    (Malcolm always writes it). A record without that dataset (an Arkime session naming the provider, say) is left
    to the other normalizers, exactly as before Malcolm records were read."""
    if _get(src, "event.provider") != "suricata":
        return False
    dataset = _get(src, "event.dataset")
    return isinstance(dataset, str) and bool(dataset) and not dataset.startswith("suricata.")


def normalize_malcolm_suricata(hit: dict) -> TypedEvent:
    """A Suricata record as Malcolm indexes it, normalized to the typed event of the same EVE record: from the EVE
    line when the record still carries it, otherwise from the places Malcolm moved each EVE field to, which every
    typed field's origin names. The sensor is host.name, else Malcolm's `node`."""
    src, nid = hit["_source"], hit["_id"]
    node = src.get("node")
    host = _get(src, "host.name") or (node if isinstance(node, str) and node else None)
    raw = _get(src, "event.original") or src.get("message")
    if raw:
        try:
            eve = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"suricata event.original is not JSON: {e}") from e
        return _suricata_event(hit, eve, f"{nid}:event.original#eve", host=host)
    eve, origins, caveats, malformed, extra = _malcolm_eve(src, nid)
    event = _suricata_event(hit, eve, f"{nid}:suricata", origins=origins, caveats=caveats, malformed=malformed,
                            host=host)
    event.fields.update(extra)
    return event


def _ordered_strings(value, path: str, bad: list[str]) -> list[str] | None:
    """A string-or-array-of-strings field in its own order, duplicates removed; None when absent."""
    if _absent(value):
        return None
    items = value if isinstance(value, list) else [value]
    if not all(isinstance(item, str) for item in items):
        bad.append(path)
        return None
    return list(dict.fromkeys(item for item in items if item)) or None


def _malcolm_app_proto(src: dict, s: dict, dataset: str, bad: list[str]) -> tuple[str | list[str] | None, str | None]:
    """EVE app_proto read back from Malcolm's network.protocol (a list: candidates the record does not tell apart),
    and the caveat when it cannot be read back exactly."""
    protocols = _ordered_strings(_get(src, "network.protocol"), "network.protocol", bad)
    if "network.protocol" in bad or dataset not in _EVE_APP_PROTO_TYPES:
        return None, None
    if not protocols:
        return None, MALCOLM_NO_APP_PROTO_CAVEAT
    head = protocols[0]
    later = set()
    for path in _MALCOLM_AFTER_APP_PROTO:
        value = _get(s, path)
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and item:
                later.add(_MALCOLM_PROTOCOL_RENAMED.get(item.lower(), item.lower()))
    if head == "icmp":
        # inferred from the record's ICMP fields: Suricata has no ICMP application protocol, so none was written
        return None, None
    if head in later:
        return None, MALCOLM_NO_APP_PROTO_CAVEAT
    if head == "ftp":
        return list(MALCOLM_FTP_CANDIDATES), MALCOLM_FTP_CAVEAT
    return _MALCOLM_PROTOCOL_ORIGINAL.get(head, head), None


def _malcolm_techniques(src: dict, bad: list[str]) -> list[str] | None:
    """alert.metadata.mitre_technique_id read back from threat.technique.id and .subtechnique.id: every dotted id,
    then every parent id not implied by one of them. Malcolm adds each sub-technique's parent to threat.technique.id
    whether or not the rule listed it, so a parent the rule listed beside its own sub-technique cannot be told from
    a derived one and is not kept (["T1071", "T1071.001"] reads back as ["T1071.001"])."""
    parents = _ordered_strings(_get(src, "threat.technique.id"), "threat.technique.id", bad)
    subs = _ordered_strings(_get(src, "threat.technique.subtechnique.id"), "threat.technique.subtechnique.id", bad)
    if parents is None and subs is None:
        return None
    implied = {sub.split(".", 1)[0] for sub in subs or []}
    return (subs or []) + [parent for parent in parents or [] if parent not in implied]


def _malcolm_category(src: dict, bad: list[str]) -> tuple[bool, str | None]:
    """(present, value) of the alert's classtype category in rule.category. Malcolm's 11_suricata_logs.conf merges
    the alert's category (an empty one included), or else alert.metadata.former_category, into rule.category and
    then appends a MITRE tactic name, else technique name, else framework (threat.tactic.name, threat.technique.name,
    threat.framework). That appended tail is removed first, so a tactic name is never taken for the category."""
    value = _get(src, "rule.category")
    if value is None:
        return False, None
    values = value if isinstance(value, list) else [value]
    if not all(isinstance(item, str) for item in values):
        bad.append("rule.category")
        return False, None
    for path in ("threat.tactic.name", "threat.technique.name", "threat.framework"):
        tail = _get(src, path)
        if tail not in (None, "", []):
            tail = tail if isinstance(tail, list) else [tail]
            if 0 < len(tail) <= len(values) and values[len(values) - len(tail):] == tail:
                values = values[:len(values) - len(tail)]
            break
    return (True, values[0]) if values else (False, None)


def _malcolm_eve(src: dict, nid: str) -> tuple[dict, dict[str, str], list[str], list[str], dict[str, FieldValue]]:
    """(EVE record, typed-field origins for values read outside suricata.*, caveats, malformed native paths, typed
    fields with no EVE counterpart)."""
    s = src.get("suricata")
    if not isinstance(s, dict):
        raise TypeError("Malcolm suricata record has no suricata object")
    dataset = _get(src, "event.dataset")
    if not isinstance(dataset, str) or not dataset:
        raise ValueError(f"Malcolm suricata event.dataset is {type(dataset).__name__}, not one event type")
    eve = {**s, "event_type": dataset}
    eve.pop("app_proto", None)
    origins: dict[str, str] = {}
    caveats: list[str] = []
    bad: list[str] = []
    for key, path, typed in _MALCOLM_MOVED:
        value = _get(src, path)
        if value is not None:
            eve[key] = value
            origins[typed] = f"{nid}:{path}"
    written = _get(src, "network.community_id")
    if written not in (None, ""):
        eve["community_id"] = written
        origins["network.community_id"] = f"{nid}:network.community_id"
    else:
        origins["network.community_id"] = (f"{nid}:source.ip+source.port+destination.ip+destination.port+"
                                           f"network.transport#computed:community_id_v1")
    extra: dict[str, FieldValue] = {}
    app_proto, caveat = _malcolm_app_proto(src, s, dataset, bad)
    if isinstance(app_proto, list):
        extra["network.app_proto_candidates"] = fv(app_proto, f"{nid}:network.protocol#derived:app_proto_candidates")
    elif app_proto is not None:
        eve["app_proto"] = app_proto
        origins["network.app_proto"] = f"{nid}:network.protocol#derived:app_proto"
    if caveat:
        caveats.append(caveat)
    if dataset == "alert" or "alert" in s:
        alert = s.get("alert", {})
        if isinstance(alert, dict):
            alert = dict(alert)
            for key, path in (("signature", "rule.name"), ("signature_id", "rule.id")):
                value = _get(src, path)
                if value is not None:
                    alert[key] = value
                    origins[f"alert.{key}"] = f"{nid}:{path}"
            present, category = _malcolm_category(src, bad)
            if present:
                alert["category"] = category
                origins["alert.category"] = f"{nid}:rule.category#derived:classtype"
            techniques = _malcolm_techniques(src, bad)
            metadata = alert.get("metadata") or {}
            if techniques and isinstance(metadata, dict):
                alert["metadata"] = {**metadata, "mitre_technique_id": techniques}
                origins["alert.mitre_technique_id"] = (f"{nid}:threat.technique.subtechnique.id+threat.technique.id"
                                                       f"#derived:technique-ids")
        eve["alert"] = alert
    moved_tls = {key: _get(src, path) for key, path in _MALCOLM_MOVED_TLS if _get(src, path) is not None}
    if moved_tls:
        block = s.get("tls", {})
        if isinstance(block, dict):
            eve["tls"] = {**block, **moved_tls}
            origins.update({f"tls.{key}": f"{nid}:{path}" for key, path in _MALCOLM_MOVED_TLS if key in moved_tls})
    if "flow" not in s and isinstance(s.get("netflow"), dict):
        origins.update({f"flow.{key}": f"{nid}:suricata.netflow.{key}" for key in s["netflow"]})
    tags = src.get("tags")
    tags = {t for t in (tags if isinstance(tags, list) else [tags]) if isinstance(t, str)}
    if "proto_parse_failed" in tags:
        caveats.append(MALCOLM_PARSE_FAILED_CAVEAT)
    if "_missing_timestamp" in tags:
        caveats.append(MALCOLM_MISSING_TIMESTAMP_CAVEAT)
    return eve, origins, caveats, bad, extra


# ---------------------------------------------------------------------------------------------
# Suricata EVE as Filebeat's suricata module and Elastic Agent's Suricata integration index it
# ---------------------------------------------------------------------------------------------
# Both decode each EVE line into suricata.eve.* under the dataset "suricata.eve" (event.dataset, and for the Agent
# data_stream.dataset too), move part of the record to ECS fields, and index it without the line once the shipper
# drops event.original. The moves were read from these files (nothing is copied from them):
# - Filebeat, x-pack/filebeat/module/suricata/eve: config/eve.yml (Beats processors, before ingest), ingest/pipeline.yml,
#   ingest/dns.yml, ingest/dns-answer-v1.yml, ingest/dns-answer-v2.yml, ingest/http.yml and ingest/tls.yml. The files
#   are identical on the 7.17, 8.19 and main branches, so one table covers 7.17 and 8.x/9.x.
# - Elastic Agent, elastic/integrations packages/suricata (2.27.1, for Kibana 8.11+ and 9.x):
#   data_stream/eve/elasticsearch/ingest_pipeline/default.yml, dns.yml, dns-answer-v1.yml, dns-answer-v2.yml and
#   tls.yml. Where the Agent differs from Filebeat the table says so.
# Every other EVE key the EVE normalizer reads stays where Suricata wrote it, under suricata.eve.*: the alert's
# signature, signature_id and category (copied to rule.*, never moved), alert.metadata.signature_severity, flow.state,
# netflow, tcp, icmp_type/icmp_code, community_id, the dns block (copied to dns.*), the tls block (copied to tls.*),
# ssh, and http.http_content_type. A value still found in place is read there: a pipeline that skipped a move left it.
#
# How each move is read back:
# - exact: renamed or copied unchanged.
# - lowercased: renamed and lowercased; the typed value is lowercased in every shape.
# - millisecond: rewritten as an ISO-8601 time to the millisecond (Beats' @timestamp, the ingest date processor);
#   the instant is kept below 1 ms, the sensor's zone offset is not. Typed time values compare as instants.
# - string: converted to a string in place; read back as the integer it spells.
# - app_proto: lowercased, copied to network.protocol unless "failed", "template" or "template-rust", then removed.
#   For the event types that carry app_proto (alert, flow, netflow, fileinfo) the event-type table sets no protocol,
#   so network.protocol is app_proto exactly; its absence means none, or one of the dropped values (caveat).
# - action: removed after its value was appended to event.type, "blocked" written as "denied". Suricata writes
#   "allowed" or "blocked": exactly one of "allowed"/"denied" in event.type (less the flow-state "start"/"end") reads
#   back exactly; any other value, or both, leaves the action absent (caveat).
# - templated: Filebeat copies the value through a double-brace Mustache template, which Elasticsearch's ingest
#   templates escape as a JSON string body (a quote, a backslash and control characters are backslash-escaped); the
#   escape is inverted exactly. The Agent copies it (copy_from) or uses a triple-brace template: no escape. A Filebeat
#   value that is not a valid escaped body is left absent (caveat). Filebeat's main pipeline also removes the method
#   and user agent of an http block whose record is not the "http" protocol (an http2 alert, say) without copying
#   them (caveat).
# - dns_answers: on version-2 answer records only, renamed to dns.answers with rrname, rrtype and rdata renamed to
#   name, type and data; read back with the names restored.
# - removed: dns.version and dns.grouped are removed. The version is read back from the record's layout (a query
#   names none; a version-1 answer keeps its own rrname/rrtype/ttl/rdata, which the version-1 answer pipeline copies
#   to dns.answers; a version-2 answer's list is renamed; "request"/"response" are version 3's types); grouped
#   answers are lost (caveat on a version-2 answer that keeps no answer list).
# - trailing_dot: a trailing "." is removed in place (RFC 6066 server names carry none); the value read is the
#   shipper's, with a caveat.
# - distinguished_name: the subject and issuer are copied to tls.server.subject/issuer (templated, so escaped by
#   Filebeat), then "\," is removed in place (Filebeat: both; the Agent: the issuer only). The copy, unescaped for
#   Filebeat, is the name exactly; without a copy the TLS pipeline did not run and the in-place value is exact.
ELASTIC_SURICATA_MOVES = (
    # EVE key, typed field, indexed path(s) in the order read, how
    ("src_ip", "source.ip", ("source.address", "source.ip"), "exact"),
    ("dest_ip", "destination.ip", ("destination.address", "destination.ip"), "exact"),
    ("src_port", "source.port", ("source.port",), "exact"),
    ("dest_port", "destination.port", ("destination.port",), "exact"),
    ("proto", "network.transport", ("network.transport",), "lowercased"),
    ("timestamp", None, ("@timestamp",), "millisecond"),
    ("flow_id", "suricata.flow_id", ("suricata.eve.flow_id",), "string"),
    ("app_proto", "network.app_proto", ("network.protocol",), "app_proto"),
    ("alert.severity", "alert.severity", ("event.severity",), "exact"),
    ("alert.action", "alert.action", ("event.type",), "action"),
    ("alert.metadata.mitre_technique_id", "alert.mitre_technique_id", ("threat.technique.id",), "exact"),
    ("flow.bytes_toserver", "flow.bytes_toserver", ("source.bytes",), "exact"),
    ("flow.bytes_toclient", "flow.bytes_toclient", ("destination.bytes",), "exact"),
    ("flow.pkts_toserver", "flow.pkts_toserver", ("source.packets",), "exact"),
    ("flow.pkts_toclient", "flow.pkts_toclient", ("destination.packets",), "exact"),
    ("flow.start", "flow.start", ("event.start",), "millisecond"),
    ("flow.end", "flow.end", ("event.end",), "millisecond"),
    ("fileinfo.filename", "file.name", ("file.path",), "exact"),
    ("fileinfo.size", "file.size", ("file.size",), "exact"),
    # Filebeat renames the hostname; the Agent appends it through a triple-brace template (and de-duplicates the list)
    ("http.hostname", "http.hostname", ("destination.domain",), "exact"),
    ("http.url", "url.original", ("url.original",), "exact"),
    ("http.http_user_agent", "user_agent.original", ("user_agent.original",), "exact"),
    # Filebeat sets the method through a template; the Agent copies it
    ("http.http_method", "http.request.method", ("http.request.method",), "templated"),
    ("http.status", "http.response.status_code", ("http.response.status_code",), "exact"),
    ("http.length", "http.response.length", ("http.response.body.bytes",), "exact"),
    ("http.http_refer", None, ("http.request.referrer",), "exact"),
    ("dns.answers", "dns.answers", ("dns.answers",), "dns_answers"),
    ("dns.version", "dns.version", (), "removed"),
    ("dns.grouped", None, (), "removed"),
    ("tls.sni", "tls.client.server_name", ("suricata.eve.tls.sni",), "trailing_dot"),
    ("tls.subject", None, ("suricata.eve.tls.subject", "tls.server.subject"), "distinguished_name"),
    ("tls.issuerdn", None, ("suricata.eve.tls.issuerdn", "tls.server.issuer"), "distinguished_name"),
)
ELASTIC_DATASET = "suricata.eve"
ELASTIC_RECONSTRUCTED_CAVEAT = "Reconstructed from fields the shipper parsed; the EVE record was not indexed."
ELASTIC_NO_APP_PROTO_CAVEAT = (
    "The shipper drops Suricata's app_proto values 'failed', 'template' and 'template-rust': no application protocol "
    "on this record means Suricata identified none or reported one of those")
ELASTIC_ESCAPED_CAVEAT = "The shipper's escaped copy of these values is not a valid escaped string: not typed: "
ELASTIC_ACTION_CAVEAT = ("The alert's action cannot be read back from event.type (not exactly one of 'allowed' and "
                         "'denied'): not typed")
ELASTIC_SNI_CAVEAT = "The shipper removes a trailing '.' from the TLS server name; the name is typed as indexed"
ELASTIC_HTTP_DROPPED_CAVEAT = ("Filebeat removes the HTTP method and user agent of a record whose protocol is not "
                               "'http' without copying them: not typed")
_ELASTIC_ACTIONS = {"allowed": "allowed", "denied": "blocked"}
ELASTIC_GROUPED_CAVEAT = ("The shipper removes Suricata's grouped DNS answers: this version-2 answer kept no answer "
                          "list, so answers logged only in the grouped form are not typed")
ELASTIC_DNS_VERSION_CAVEAT = "The shipper removes the DNS record's version, and its layout does not tell it: not typed"
# The event types the sweep reports as seen in this shape; any other is counted as "other" (the table stays bounded).
ELASTIC_EVENT_TYPES = ("alert", "flow", "netflow", "dns", "http", "fileinfo", "tls", "ssh")
_ELASTIC_V1_ANSWER = (("name", "rrname"), ("data", "rdata"), ("type", "rrtype"), ("ttl", "ttl"))


def _eve_json(raw) -> dict | None:
    """The EVE record a document still carries as JSON text, else None."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        eve = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return eve if isinstance(eve, dict) else None


def elastic_suricata_dataset(src: dict) -> bool:
    """A document of Filebeat's suricata module or the Agent's Suricata integration (dataset "suricata.eve" on either
    dataset field) that holds the parsed EVE record under suricata.eve with its event type."""
    if ELASTIC_DATASET not in (_get(src, "event.dataset"), _get(src, "data_stream.dataset")):
        return False
    eve = _get(src, "suricata.eve")
    return isinstance(eve, dict) and "event_type" in eve


def is_elastic_suricata(src: dict) -> bool:
    """An Elastic-shipped Suricata document that no longer carries its EVE line (in event.original or message): it is
    rebuilt from the fields the shipper parsed. One that still carries the line is read from the line."""
    return (elastic_suricata_dataset(src) and _eve_json(_get(src, "event.original")) is None
            and _eve_json(src.get("message")) is None)


def _set_path(record: dict, path: str, value) -> bool:
    """Put `value` at a dotted path of an EVE record, creating objects on the way; False when a step is not one."""
    parts = path.split(".")
    current = record
    for part in parts[:-1]:
        nxt = current.setdefault(part, {})
        if not isinstance(nxt, dict):
            return False
        current = nxt
    current[parts[-1]] = value
    return True


def _indexed(src: dict, paths) -> tuple[object, str | None]:
    """The first indexed value among `paths`, with its path."""
    for path in paths:
        value = _get(src, path)
        if value is not None:
            return value, path
    return None, None


def _single_string(value) -> str | None:
    """A string, or a list holding one distinct string (a de-duplicated append), else None."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        distinct = {item for item in value if isinstance(item, str)}
        if len(distinct) == 1 and all(isinstance(item, str) for item in value):
            return next(iter(distinct))
    return None


def _elastic_action(src: dict) -> tuple[str | None, bool]:
    """(alert.action, unreadable) read back from event.type: exactly one of "allowed"/"denied" beside the flow-state
    marks; any other value, or both, is unreadable."""
    values = _get(src, "event.type")
    values = values if isinstance(values, list) else [] if values is None else [values]
    candidates = [value for value in dict.fromkeys(values) if value not in ("start", "end")]
    if not candidates:
        return None, False
    if len(candidates) > 1 or candidates[0] not in _ELASTIC_ACTIONS:
        return None, True
    return _ELASTIC_ACTIONS[candidates[0]], False


def _filebeat_shipped(src: dict) -> bool:
    """Filebeat's module (its double-brace templates escape) rather than the Agent's integration (data_stream.*)."""
    return _get(src, "data_stream.dataset") is None


def _unescaped(text: str) -> str | None:
    """A double-brace ingest template's output read back: the JSON string body unescaped, None when it is not one."""
    try:
        value = json.loads(f'"{text}"')
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, str) else None


def _elastic_dns(src: dict, d: dict, nid: str, origins: dict[str, str], caveats: list[str], bad: list[str]) -> None:
    """Restore a dns block's version and its version-2 answer list."""
    kind = d.get("type")
    version, how = None, None
    if kind in ("request", "response"):
        version, how = 3, "request/response type"
    elif kind == "query":
        how = "query"                        # Suricata's query records before version 3 name no version
    elif kind == "answer":
        renamed = _get(src, "dns.answers")
        v1 = {key: d[native] for key, native in _ELASTIC_V1_ANSWER if d.get(native) is not None}
        if "ttl" in d or "rdata" in d or (isinstance(renamed, list) and v1 and renamed == [v1]):
            how = "version-1 answer"         # one answer, kept in place; dns.answers is the pipeline's copy of it
        elif "answers" in d:
            caveats.append(ELASTIC_DNS_VERSION_CAVEAT)
        elif isinstance(renamed, list):
            answers = []
            for item in renamed:
                if not isinstance(item, dict):
                    bad.append("dns.answers")
                    answers = None
                    break
                restored = {k: v for k, v in item.items() if k not in ("name", "type", "data")}
                restored.update({native: item[key] for key, native in (("name", "rrname"), ("type", "rrtype"),
                                                                        ("data", "rdata")) if key in item})
                answers.append(restored)
            if answers is not None:
                d["answers"] = answers
                origins["dns.answers"] = f"{nid}:dns.answers"
            version, how = 2, "version-2 answer"
        elif d.get("rrname") is not None:
            version, how = 2, "version-2 answer"
            caveats.append(ELASTIC_GROUPED_CAVEAT)
        else:
            caveats.append(ELASTIC_DNS_VERSION_CAVEAT)
    elif kind is not None:
        caveats.append(ELASTIC_DNS_VERSION_CAVEAT)
    if version is not None:
        d["version"] = version
        origins["dns.version"] = f"{nid}:suricata.eve.dns.type#derived:version ({how})"


def _elastic_names(src: dict, t: dict, escaped: list[str]) -> None:
    """Restore the certificate subject and issuer names (see `distinguished_name` above)."""
    filebeat = _filebeat_shipped(src)
    for key, copy_path in (("subject", "tls.server.subject"), ("issuerdn", "tls.server.issuer")):
        copied = _get(src, copy_path)
        if not isinstance(copied, str) or not copied:
            # the TLS pipeline copies every non-empty name before changing it: without a copy it did not run
            continue
        name = _unescaped(copied) if filebeat else copied
        if name is None:
            t.pop(key, None)
            escaped.append(copy_path)
        else:
            t[key] = name


def elastic_suricata_eve(src: dict, nid: str = "") -> tuple[dict, dict[str, str], list[str], list[str]]:
    """The EVE record of a Filebeat- or Agent-shipped Suricata document, rebuilt from suricata.eve.* and the fields
    the shipper moved it to (`ELASTIC_SURICATA_MOVES`). Returns (EVE record, origins of typed fields read outside
    suricata.eve, caveats, malformed native paths). A document the shipper's pipeline failed on is an error: its
    fields may be incomplete."""
    s = _get(src, "suricata.eve")
    if not isinstance(s, dict):
        raise TypeError("suricata.eve is not an object")
    failure = _get(src, "error.message")
    if failure not in (None, "", []):
        raise ValueError("the shipper's ingest pipeline failed on this record, so its fields may be incomplete")
    eve = json.loads(json.dumps(s))
    et = eve.get("event_type")
    origins: dict[str, str] = {}
    caveats = [ELASTIC_RECONSTRUCTED_CAVEAT]
    bad: list[str] = []
    escaped: list[str] = []
    filebeat = _filebeat_shipped(src)
    has_http = et == "http" or isinstance(eve.get("http"), dict)
    if filebeat and isinstance(eve.get("http"), dict) and _get(src, "network.protocol") != "http" and not any(
            key in eve["http"] for key in ("http_method", "http_user_agent")):
        caveats.append(ELASTIC_HTTP_DROPPED_CAVEAT)
    has_flow = et != "netflow"
    for key, typed, paths, how in ELASTIC_SURICATA_MOVES:
        if how in ("removed", "dns_answers", "distinguished_name", "trailing_dot") or key == "timestamp":
            continue                      # read below with its block; the record's time is @timestamp itself
        block = key.split(".", 1)[0] if "." in key else None
        if (block == "http" and not has_http) or (block == "flow" and not has_flow) \
                or (block == "fileinfo" and et != "fileinfo" and not isinstance(eve.get("fileinfo"), dict)) \
                or (block == "alert" and et != "alert" and not isinstance(eve.get("alert"), dict)):
            continue
        if how == "string":
            value = eve.get(key)
            if isinstance(value, str):
                if re.fullmatch(r"[0-9]+", value):
                    eve[key] = int(value)
                    origins[typed] = f"{nid}:{paths[0]}#derived:integer"
                else:
                    bad.append(key)
                    eve.pop(key)
            continue
        if _get(eve, key) is not None:
            continue                      # still in place: the pipeline did not move it
        if how == "app_proto":
            if et not in _EVE_APP_PROTO_TYPES:
                continue
            value = _get(src, paths[0])
            if value is None:
                caveats.append(ELASTIC_NO_APP_PROTO_CAVEAT)
            elif isinstance(value, str) and value:
                eve[key] = value
                origins[typed] = f"{nid}:{paths[0]}"
            else:
                bad.append(paths[0])
            continue
        if how == "action":
            value, ambiguous = _elastic_action(src)
            if ambiguous:
                caveats.append(ELASTIC_ACTION_CAVEAT)
            elif value is not None and _set_path(eve, key, value):
                origins[typed] = f"{nid}:event.type#derived:alert.action"
            continue
        value, path = _indexed(src, paths)
        if value is None:
            continue
        if how in ("templated", "exact") and block == "http" and isinstance(value, list):
            # the Agent appends the hostname to destination.domain: one distinct value
            value = _single_string(value)
            if value is None:
                bad.append(path)
                continue
        if how == "templated" and filebeat:
            if not isinstance(value, str):
                bad.append(path)
                continue
            value = _unescaped(value)
            if value is None:
                escaped.append(path)
                continue
        elif how == "lowercased" and isinstance(value, str):
            value = value.lower()
        if not _set_path(eve, key, value):
            bad.append(key)
            continue
        if typed is not None:
            origins[typed] = f"{nid}:{path}"
    if "community_id" not in eve or eve.get("community_id") in (None, ""):
        tuple_paths = [origins.get(name, f"{nid}:suricata.eve.{native}").removeprefix(f"{nid}:") for name, native in (
            ("source.ip", "src_ip"), ("source.port", "src_port"), ("destination.ip", "dest_ip"),
            ("destination.port", "dest_port"), ("network.transport", "proto"))]
        origins["network.community_id"] = f"{nid}:{'+'.join(tuple_paths)}#computed:community_id_v1"
    d = eve.get("dns")
    if isinstance(d, dict):
        _elastic_dns(src, d, nid, origins, caveats, bad)
    t = eve.get("tls")
    if isinstance(t, dict):
        if isinstance(t.get("sni"), str) and t["sni"]:
            caveats.append(ELASTIC_SNI_CAVEAT)
        _elastic_names(src, t, escaped)
    if escaped:
        caveats.append(ELASTIC_ESCAPED_CAVEAT + ", ".join(escaped))
    return eve, origins, caveats, bad


def normalize_elastic_suricata(hit: dict) -> TypedEvent:
    """A Filebeat- or Agent-shipped Suricata document without its EVE line, normalized to the typed event of the
    same EVE record: every typed value read outside suricata.eve.* names its indexed path."""
    src, nid = hit["_source"], hit["_id"]
    eve, origins, caveats, malformed = elastic_suricata_eve(src, nid)
    return _suricata_event(hit, eve, f"{nid}:suricata.eve", origins=origins, caveats=caveats, malformed=malformed)


def elastic_event_type_key(src: dict) -> str:
    """The shape-table key of an Elastic-shipped Suricata document: its EVE event type, or "other"."""
    et = _get(src, "suricata.eve.event_type")
    return f"suricata.eve.elastic:{et if et in ELASTIC_EVENT_TYPES else 'other'}"


# ---------------------------------------------------------------------------------------------
# Arkime SPI session records (read from the session indices)
# ---------------------------------------------------------------------------------------------
# Arkime 6.x stores `cert` and `dns` as arrays of objects, and its string fields (ja3, hassh, versions, tags) as
# arrays. Each is read with the shared contract above; a block of an undocumented type is dropped and listed in
# parse.malformed, and the rest of the session record is kept.

IP_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp"}
ARKIME_FIELDS = (
    # typed name, native path: values passed through as stored
    ("source.ip", "source.ip"), ("source.port", "source.port"), ("destination.ip", "destination.ip"),
    ("destination.port", "destination.port"), ("network.community_id", "network.community_id"),
    ("source.bytes", "source.bytes"), ("source.packets", "source.packets"),
    ("destination.bytes", "destination.bytes"), ("destination.packets", "destination.packets"),
    ("client.bytes", "client.bytes"), ("server.bytes", "server.bytes"),
    ("http.hostname", "http.host"), ("url.path", "http.uri"), ("user_agent.original", "http.useragent"),
    ("http.request.method", "http.method"), ("http.response.status_code", "http.statuscode"),
    ("network.protocols", "protocol"),
)
# typed name, native path: string-or-array fields read as sorted distinct string lists (see the contract above)
ARKIME_STRING_LISTS = (
    ("tls.ja3", "tls.ja3"), ("tls.ja3s", "tls.ja3s"), ("tls.ja4", "tls.ja4"), ("tls.version", "tls.version"),
    ("ssh.hassh", "ssh.hassh"), ("ssh.hassh_server", "ssh.hasshServer"), ("ssh.version", "ssh.version"),
    ("http.body_magic", "http.bodyMagic"), ("arkime.tags", "tags"),
)
# Arkime's per-session TCP flag counters: typed suffix, native key
ARKIME_TCP_FLAGS = (("syn", "syn"), ("syn_ack", "syn-ack"), ("ack", "ack"), ("psh", "psh"), ("fin", "fin"),
                    ("rst", "rst"), ("urg", "urg"))
# keys of an Arkime DNS answer object that describe the answer rather than carry its data
_ARKIME_ANSWER_META = {"type", "class", "ttl", "name", "priority"}


def is_arkime_session(src: dict) -> bool:
    return "firstPacket" in src and "lastPacket" in src and isinstance(src.get("source"), dict)


def _epoch_ms(value) -> datetime:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"Arkime packet time is not epoch milliseconds: {value!r}")
    return datetime.fromtimestamp(value / 1000, UTC)


def _arkime_path(src: dict, path: str, bad: list[str]):
    """A nested value; a non-object on the way is malformed, not merely absent."""
    cur = src
    parts = path.split(".")
    for i, part in enumerate(parts):
        if cur is None:
            return None
        if not isinstance(cur, dict):
            bad.append(".".join(parts[:i]))
            return None
        cur = cur.get(part)
    return cur


def _arkime_certificates(src: dict, nid: str, bad: list[str], caveats: list[str]) -> dict:
    objs = _objects(src.get("cert"), "cert", bad)
    if not objs:
        return {}
    certs = []
    for i, obj in enumerate(objs):
        p = f"cert[{i}]"
        names = {key: _strings(obj.get(native), f"{p}.{native}", bad) or []
                 for key, native in (("subject_cn", "subjectCN"), ("subject_on", "subjectON"),
                                     ("issuer_cn", "issuerCN"), ("issuer_on", "issuerON"), ("alt_names", "alt"))}
        serial = _hex_id(obj.get("serial"), f"{p}.serial", bad)
        certs.append({**names, "subject_dn": None, "issuer_dn": None,
                      "not_before": _cert_time(obj.get("notBefore"), f"{p}.notBefore", bad),
                      "not_after": _cert_time(obj.get("notAfter"), f"{p}.notAfter", bad),
                      "valid_days": _count(obj.get("validDays"), f"{p}.validDays", bad),
                      "sha1": _hex_id(obj.get("hash"), f"{p}.hash", bad),
                      "serial": serial.replace(":", "") if serial else None})
    return _certificate_fields(certs, f"{nid}:cert", caveats)


def _arkime_answer(obj: dict, path: str, bad: list[str]) -> dict:
    """One Arkime DNS answer. Its data is the one string held under a non-descriptive key (ip, cname, nameserver,
    mx, txt, ...); with none, or several, the data is unknown (None), never a pick."""
    held = [v for k, v in obj.items() if k not in _ARKIME_ANSWER_META and not k.endswith("Cnt")]
    values = [v for v in held if isinstance(v, str)] + [x for v in held if isinstance(v, list) for x in v
                                                        if isinstance(x, str)]
    return {"name": _scalar_str(obj.get("name"), f"{path}.name", bad),
            "type": _scalar_str(obj.get("type"), f"{path}.type", bad),
            "ttl": _count(obj.get("ttl"), f"{path}.ttl", bad),
            "data": values[0] if len(values) == 1 else None}


def _arkime_dns(src: dict, nid: str, bad: list[str]) -> dict:
    objs = _objects(src.get("dns"), "dns", bad)
    if not objs:
        return {}
    names, types, codes, answers = set(), set(), set(), []
    for i, obj in enumerate(objs):
        p = f"dns[{i}]"
        names.update(_strings(obj.get("host"), f"{p}.host", bad) or [])
        types.update(_strings(obj.get("qt"), f"{p}.qt", bad) or [])
        codes.update(_strings(obj.get("status"), f"{p}.status", bad) or [])
        for j, ans in enumerate(_objects(obj.get("answers"), f"{p}.answers", bad) or []):
            answers.append(_arkime_answer(ans, f"{p}.answers[{j}]", bad))
    f = _dns_name_fields(names, types, codes, f"{nid}:dns")
    if answers:
        f["dns.answers"] = fv(answers, f"{nid}:dns.answers")
    return f


def normalize_arkime_session(hit: dict) -> TypedEvent:
    """One net_session per Arkime SPI record. Arkime saves long sessions in several records (one per
    save interval) sharing the 5-tuple and community ID; each record is one event, and rules that need
    the whole connection stitch them by community ID. Handshake fields (tls, ssh, cert) are on the first
    record only; every record of a split session carries rootId naming the first, and a record whose
    rootId is not its own id is marked arkime.continuation."""
    src, nid, ref = hit["_source"], hit["_id"], _ref(hit)
    first, last = _epoch_ms(src.get("firstPacket")), _epoch_ms(src.get("lastPacket"))
    f = {}
    bad: list[str] = []
    caveats: list[str] = []
    for typed, native in ARKIME_FIELDS:
        v = _get(src, native)
        if v not in (None, [], ""):
            f[typed] = fv(v, f"{nid}:{native}")
    for typed, native in ARKIME_STRING_LISTS:
        values = _strings(_arkime_path(src, native, bad), native, bad, lower=typed in _HEX_DIGESTS)
        if values:
            f[typed] = fv(values, f"{nid}:{native}")
    flags = src.get("tcpflags")
    if isinstance(flags, dict):
        for typed, native in ARKIME_TCP_FLAGS:
            count = _count(flags.get(native), f"tcpflags.{native}", bad)
            if count is not None:
                f[f"tcp.flags.{typed}"] = fv(count, f"{nid}:tcpflags.{native}")
    elif not _absent(flags):
        bad.append("tcpflags")
    icmp = src.get("icmp")
    if isinstance(icmp, dict):
        for typed, native in (("icmp.type", "type"), ("icmp.code", "code")):
            number = _icmp_value(icmp.get(native), typed, bad)
            if number is not None:
                f[typed] = fv(number, f"{nid}:icmp.{native}")
    elif not _absent(icmp):
        bad.append("icmp")
    root = _scalar_str(src.get("rootId"), "rootId", bad)
    if root is not None:
        f["arkime.root_id"] = fv(root, f"{nid}:rootId")
        f["arkime.continuation"] = fv(root != nid, f"{nid}:rootId#derived:differs-from-own-id")
    f.update(_arkime_certificates(src, nid, bad, caveats))
    f.update(_arkime_dns(src, nid, bad))
    if bad:
        f["parse.malformed"] = fv(sorted(set(bad)), f"{nid}:#malformed")
    proto = src.get("ipProtocol")
    if proto is not None:
        f["network.transport"] = fv(IP_PROTOCOLS.get(proto, str(proto)), f"{nid}:ipProtocol")
    f["flow.start"] = fv(first.isoformat(), f"{nid}:firstPacket")
    f["flow.end"] = fv(last.isoformat(), f"{nid}:lastPacket")
    f["session.duration_s"] = fv(round((last - first).total_seconds(), 3), f"{nid}:lastPacket-firstPacket")
    f["arkime.node"] = fv(src.get("node"), f"{nid}:node")
    return TypedEvent(id=event_id("net_session", [ref]), family="net_session", ts=first, host=src.get("node"),
                      fields={k: v for k, v in f.items() if v.value is not None}, raw=[ref],
                      normalizer=NORMALIZER_VERSION, caveats=caveats)


# Companion record types an exec or socket event holds at most once (EXECVE may repeat: continuation records)
_SINGLE_COMPANIONS = (EXEC_COMPANIONS | SOCKET_COMPANIONS) - {"EXECVE"}

SINGLE = {
    "systemd.journal": normalize_journal,
    "apache.access": normalize_apache_access,
    "apache.error": normalize_apache_error,
}


def _observed_or_skip(events: list[TypedEvent], skips: dict[str, int], errors: list[tuple[str, str]], host: str,
                      members: list[tuple[dict, AuditRecord]], reason: str | None) -> None:
    """An audit group that is no event of its own family (`reason`): the process its SYSCALL record names, as a
    process_observed event; counted as skipped only when no record names one (`reason` None: the caller counts it).
    A group that cannot be read is one error, tagged so that only rules reading observations are partial."""
    try:
        observed = normalize_observed_group(host, members)
    except (AuditParseError, ValueError, KeyError, TypeError, OverflowError, OSError) as e:
        errors.append((members[0][0]["_id"], f"linux.audit.observed: {e}"))
        return
    if observed is not None:
        events.append(observed)
    elif reason is not None:
        skips[reason] += 1


def observed_record(hit: dict, boot: list | tuple | None = None) -> TypedEvent | None:
    """The process_observed view of one audit SYSCALL record (a hit as the source returned it), exactly as
    `normalize_observed_group` builds it, with the boot id the hunt gave the record (`boot`: value and origin) when that
    came from another record (a journald copy, the boot-interval map). None when it is not such a record."""
    source = hit["_source"]
    raw = _get(source, "event.original") or source.get("message")
    found = match_shape(source)
    if found is not None and found[1].shape == AUDIT_EVENT:
        # one Auditbeat event document: its SYSCALL record among the records it holds
        members = [(h, r) for h, r in _auditbeat_group(hit, []) if r.type == "SYSCALL"]
        record = members[0][1] if members else None
    elif found is not None and found[1].shape == AUDIT_RECORD:
        record = audit_record_of(hit)
    elif not raw:
        return None
    else:
        record = parse_record(raw)
    if record is None or record.type != "SYSCALL":
        return None
    members = [(hit, record)]
    event = normalize_observed_group(audit_host(source, record), members)
    if event is not None:
        _audit_node_fields(event, members)
        _rebuilt_provenance(event, members)
    if event is not None and boot is not None and not event.has("host.boot.id"):
        event.fields["host.boot.id"] = fv(boot[0], boot[1])
    return event


# ---------------------------------------------------------------------------------------------
# Provenance of events built from rebuilt audit records
# ---------------------------------------------------------------------------------------------

RECONSTRUCTED_CAVEAT = "Reconstructed from fields the shipper parsed; the raw audit record was not indexed."
HEX_GUESS_CAVEAT = ("Decoded from hex: the shipper does not record whether these values were hex-encoded, and "
                    "auditd would have encoded their text")
_RAW_AUDIT_ORIGIN = re.compile(r"^(?P<id>.+?):event\.original#auditd:(?P<spec>.*)$")
_RECORD_TYPE = re.compile(r"^[A-Z_]+(?:\([A-Z]+\))?$")


_ORIGIN_PATHS = {"msg.serial": "auditd.log.sequence", "msg.timestamp": "@timestamp", "type": "auditd.log.record_type"}
_ARG_KEY = re.compile(r"^a(?:\d+|\*)$")


def _spec_path(spec: str, record: AuditRecord | None, by_type: dict[str, AuditRecord]
               ) -> tuple[str, AuditRecord | None]:
    """(the indexed path, the record) a raw-record origin spec ("SYSCALL.pid", "msg.serial",
    "USER_START:enriched.UID", a part of "SYSCALL.arch+syscall") names among rebuilt records. A spec naming a record
    type reads that record (the given one when it is of that type); a bare key reads the given record."""
    head, colon, tail = spec.partition(":")
    if colon:                                   # "<TYPE>:enriched.<KEY>"
        spec = tail
    else:
        head, _dot, rest = spec.partition(".")
        if rest and _RECORD_TYPE.match(head):
            spec = rest
        else:
            head = ""
    kind = head.split("(", 1)[0]
    if kind and _RECORD_TYPE.match(kind) and (record is None or record.type != kind):
        record = by_type.get(kind, record)
    if spec.startswith("enriched."):
        return f"auditd.log.{spec[len('enriched.'):]}", record
    if spec in _ORIGIN_PATHS:
        return _ORIGIN_PATHS[spec], record
    if _ARG_KEY.match(spec):
        return "process.args", record
    return ((record.origins or {}) if record is not None else {}).get(spec) or f"auditd.log.{spec}", record


def _rebuilt_origin(origin: str, rebuilt: dict[str, AuditRecord], by_type: dict[str, AuditRecord]) -> str:
    """An origin naming rebuilt records' indexed paths in place of their (absent) raw text."""
    parts, current, changed = [], None, False
    for part in origin.split("+"):
        m = _RAW_AUDIT_ORIGIN.match(part)
        if m is not None:
            current = rebuilt.get(m["id"])
            if current is not None:
                path, current = _spec_path(m["spec"], current, by_type)
                part, changed = f"{m['id']}:{path}", True
        elif current is not None:
            part, current = _spec_path(part, current, by_type)
        parts.append(part)
    return "+".join(parts) if changed else origin


def _rebuilt_provenance(event: TypedEvent, members: list[tuple[dict, AuditRecord]]) -> None:
    """For an event viewing a rebuilt record: origins name the indexed paths, the event says it was rebuilt, and
    any value decoded from hex on a guess is named."""
    rebuilt = {hit["_id"]: record for hit, record in members if record.reconstructed}
    cited = {ref.native_id for ref in event.raw}
    if not rebuilt or not cited & set(rebuilt):
        return
    by_type: dict[str, AuditRecord] = {}
    for _hit, record in members:
        if record.reconstructed:
            by_type.setdefault(record.type, record)
    for name, value in list(event.fields.items()):
        origin = _rebuilt_origin(value.origin, rebuilt, by_type)
        if origin != value.origin:
            event.fields[name] = fv(value.value, origin)
    first = min(cited & set(rebuilt))
    event.fields["audit.reconstructed"] = fv(True, f"{first}:auditd.log.record_type")
    if RECONSTRUCTED_CAVEAT not in event.caveats:
        event.caveats.append(RECONSTRUCTED_CAVEAT)
    guessed = sorted({f"{record.type}.{key}" for native_id, record in rebuilt.items() if native_id in cited
                      for key in record.hex_guessed})
    if guessed:
        event.caveats.append(f"{HEX_GUESS_CAVEAT}: {', '.join(guessed)}")


def _audit_group(host: str, members: list[tuple[dict, AuditRecord]], events: list[TypedEvent],
                 skips: dict[str, int], errors: list[tuple[str, str]]) -> None:
    """The typed events of one audit event's records (one group), appended to `events`."""
    counts = Counter(r.type for _, r in members)
    types = set(counts)
    # EXECVE may legitimately repeat (long-argv continuation records; merged in normalize_exec_group)
    dup = sorted(t for t, n in counts.items() if n > 1 and t in _SINGLE_COMPANIONS)
    if dup:
        errors.append((members[0][0]["_id"], f"linux.audit: ambiguous event group, duplicate {dup} records"))
        return
    if types & AUDIT_LOGIN_TYPES:
        try:
            events.append(normalize_audit_auth_group(host, members))
        except (ValueError, KeyError, TypeError) as e:
            errors.append((members[0][0]["_id"], f"linux.audit.auth: {e}"))
        return
    if types & AUDIT_ADMIN_TYPES:
        try:
            events.extend(normalize_audit_admin_group(host, members))
        except (ValueError, KeyError, TypeError) as e:
            errors.append((members[0][0]["_id"], f"linux.audit.admin: {e}"))
        return
    if "EXECVE" not in types:
        sys_rec = next((r for _, r in members if r.type == "SYSCALL"), None)
        module_call = module_syscall(sys_rec)
        if module_call is not None or "KERN_MODULE" in types:
            try:
                events.append(normalize_module_group(host, members, module_call))
                _observed_or_skip(events, skips, errors, host, members, None)
            except (AuditParseError, ValueError, KeyError) as e:
                errors.append((members[0][0]["_id"], f"linux.audit.module: {e}"))
            return
        syscall = socket_syscall(sys_rec) if sys_rec is not None else None
        file_call = file_syscall(sys_rec) if sys_rec is not None and syscall is None else None
        if file_call is not None:
            try:
                files = normalize_file_group(host, members, file_call)
                events.extend(files)
                if any(event.family == "file_access" for event in files):
                    _observed_or_skip(events, skips, errors, host, members, None)
            except Skip as s:
                _observed_or_skip(events, skips, errors, host, members, s.reason)
            except (AuditParseError, ValueError, KeyError) as e:
                # tagged by family so the sweep marks only file-change rules partial
                errors.append((members[0][0]["_id"], f"linux.audit.file: {e}"))
            return
        if syscall is None:
            arch = sys_rec.fields.get("arch", "") if sys_rec is not None else ""
            if not arch or arch in SOCKET_SYSCALLS:
                _observed_or_skip(events, skips, errors, host, members,
                                  "audit group without EXECVE, socket or file-change syscall")
            else:
                # the process is still observed; what its socket calls did is not decoded, and the skip says so
                _observed_or_skip(events, skips, errors, host, members, None)
                skips[f"audit syscall on an arch whose socket calls are not decoded ({arch})"] += 1
            return
        try:
            events.append(normalize_socket_group(host, members, syscall))
        except Skip as s:
            _observed_or_skip(events, skips, errors, host, members, s.reason)
        except (AuditParseError, ValueError, KeyError) as e:
            # tagged by family so the sweep marks only socket rules partial
            errors.append((members[0][0]["_id"], f"linux.audit.socket: {e}"))
        return
    try:
        event = normalize_exec_group(host, members)
        events.append(event)
        # the event is kept, but its command line is incomplete: the partition cannot assure a negative
        errors += [(members[0][0]["_id"], f"linux.audit: {c}") for c in event.caveats
                   if c.startswith(INCOMPLETE_ARGV_CAVEAT)]
    except Skip as s:
        skips[s.reason] += 1
    except (AuditParseError, ValueError, KeyError) as e:
        errors.append((members[0][0]["_id"], f"linux.audit: {e}"))


def _auditbeat_group(h: dict, errors: list[tuple[str, str]]) -> list[tuple[dict, AuditRecord]]:
    """The records of one Auditbeat / Auditd Manager event document: its raw lines when it carries them, else the
    records rebuilt from its fields. A line that cannot be parsed is an error; the others still form the event."""
    lines = auditbeat_lines(h["_source"])
    parsed = [line for line in lines if is_audit_line(line)]
    if not parsed:
        try:
            return auditbeat_records(h)
        except (AuditParseError, ValueError, TypeError) as e:
            errors.append((h["_id"], f"linux.audit: event cannot be rebuilt from the shipper's fields: {e}"))
            return []
    members = []
    for line in lines:
        try:
            # never the batch's parse cache: it holds one parse per hit, and this hit holds several records
            members.append((h, parse_record(line)))
        except AuditParseError as e:
            errors.append((h["_id"], f"linux.audit: unparseable record: {e}"))
    return members


NEW_WRITER_CAVEAT = "Writer identity not verifiable"
_SSH_WRITERS = frozenset({"sshd", "sshd-session", "sshd-auth"})
_WRITER_ALIASES = (
    frozenset({"sshd", "sshd-session", "sshd-auth"}),
    frozenset({"cron", "crond"}),
    frozenset({"dovecot", "imap-login", "pop3-login", "submission-login", "managesieve-login", "auth", "auth-worker"}),
    frozenset({"exim", "exim4"}),
    frozenset({"cyrus", "cyrus/imap", "cyrus/pop3", "imapd", "pop3d"}),
    frozenset({"charon", "charon-systemd", "strongswan"}),
    frozenset({"mysql", "mysqld", "mariadb", "mariadbd"}),
    frozenset({"postgres", "postgresql"}),
    frozenset({"smbd", "samba"}),
    frozenset({"named", "bind9"}),
    frozenset({"squid", "squid3"}),
    frozenset({"roundcube", "roundcubemail"}),
)
_TRUSTED_WRITER_PATHS = {"_COMM": "journald.process.name", "_EXE": "journald.process.executable",
                         "_SYSTEMD_UNIT": "systemd.unit"}


def _indexed_writer_fields(source: dict) -> dict:
    """Keep malformed trusted fields visible to validation instead of scalar coercion or omission."""
    trusted = {}
    for field, path in _TRUSTED_WRITER_PATHS.items():
        value = source
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                break
            value = value[part]
        else:
            trusted[field] = value
    return trusted


def _new_writer_identity(program: str, journal: dict | None) -> tuple[str, list[str]]:
    """Validate new fallback events only; one matching field cannot excuse another field's disagreement."""
    name = re.sub(r"\[\d+\]$", "", program).lower()
    names = next((group for group in _WRITER_ALIASES if name in group), frozenset({name}))
    units = names
    if name in _SSH_WRITERS:
        units = names | {"ssh"}
    elif name == "smtpd" or name.startswith("postfix/"):
        names, units = frozenset({name, name.rsplit("/", 1)[-1]}), frozenset({"postfix"})
    elif name == "openvpn" or name.startswith("openvpn-"):
        names, units = frozenset({name, "openvpn"}), frozenset({name, "openvpn", "openvpn-server", "openvpn-client"})
    journal = journal or {}
    present = [field for field in _TRUSTED_WRITER_PATHS if field in journal]
    for field in present:
        value = journal[field]
        if (not isinstance(value, str) or not value or len(value) > 4096
                or any(char in value for char in "\r\n\x00")):
            raise Skip(f"Writer identity mismatch: malformed trusted {field}")
        if field == "_EXE":
            value = basename_of(value)
        elif field == "_SYSTEMD_UNIT":
            if not value.endswith(".service"):
                raise Skip("Writer identity mismatch: trusted _SYSTEMD_UNIT does not name the claimed service")
            value = value[:-len(".service")].split("@", 1)[0]
        if value.lower() not in (units if field == "_SYSTEMD_UNIT" else names):
            raise Skip(f"Writer identity mismatch: identifier disagrees with trusted {field}")
    # A split helper must never be promoted into the legacy sshd stream. Prefer
    # captured comm, then executable, and preserve unverified identifier spelling.
    writer = program
    if name in _SSH_WRITERS:
        identities = [value.lower() for value in (journal.get("_COMM"), basename_of(journal.get("_EXE")))
                      if isinstance(value, str) and value.lower() in _SSH_WRITERS]
        helpers = [value for value in [*identities, program] if value in {"sshd-session", "sshd-auth"}]
        writer = next(iter(helpers or identities), program)
    return writer, [] if present else [NEW_WRITER_CAVEAT]


def _program_events(hit: dict, program: str, message: str, origin: str, *,
                    journal: dict | None = None) -> list[TypedEvent]:
    # Preserve existing untyped-message skip reasons; validate a recognized
    # fallback action or a PAM message claiming the privileged SSH service.
    parsed_records = [parsed for parsed in (parse_auth(program, message), parse_service(program, message))
                      if parsed is not None]
    ssh_pam = message.startswith("pam_unix(sshd:")
    if not parsed_records and not ssh_pam:
        return []
    writer, caveats = _new_writer_identity(program, journal)
    if ssh_pam and writer not in _SSH_WRITERS:
        raise Skip("Writer identity mismatch: PAM sshd service requires an SSH writer")
    # Use the validated writer, not an earlier parse of its chosen identifier.
    parsed_records = [parsed for parsed in (parse_auth(writer, message), parse_service(program, message))
                      if parsed is not None]
    ref = _ref(hit)
    return [TypedEvent(id=event_id(parsed.family, [ref]), family=parsed.family,
                       ts=_ts(hit["_source"]["@timestamp"]), host=_get(hit["_source"], "host.name"),
                       fields={key: fv(value, origin) for key, value in parsed.fields.items()},
                       outcome=parsed.outcome, caveats=[*parsed.caveats, *caveats], raw=[ref], normalizer=NORMALIZER_VERSION)
            for parsed in parsed_records]


def _linux_events(hit: dict, normalizer, *args) -> list[TypedEvent]:
    """Keep every existing successful normalization unchanged; extend only unsupported messages."""
    try:
        return [normalizer(hit, *args)]
    except AuditCopy:
        raise
    except Skip:
        src = hit["_source"]
        message = src.get("message")
        program = (_get(src, "syslog.identifier") or _get(src, "log.syslog.appname")
                   or _get(src, "process.name") or _get(src, "journald.process.name"))
        path = "message"
        boot_origin = None
        journal = _indexed_writer_fields(src)
        if normalizer is normalize_journal:
            journal = json.loads(_get(src, "event.original"))
            message = journal.get("MESSAGE") or message
            program = journal.get("SYSLOG_IDENTIFIER") or journal.get("_COMM")
            path = "event.original#journal:MESSAGE"
            boot_origin = f"{hit['_id']}:event.original#journal:_BOOT_ID"
        elif normalizer is normalize_journal_fields:
            journal, paths = journal_from_fields(src)
            journal.update(_indexed_writer_fields(src))
            message = journal.get("MESSAGE")
            program = journal.get("SYSLOG_IDENTIFIER") or journal.get("_COMM")
            path = paths.get("MESSAGE", "message")
            boot_origin = _indexed_origin(hit["_id"], paths)("_BOOT_ID")
        if isinstance(program, str) and isinstance(message, str):
            events = _program_events(hit, program, message, f"{hit['_id']}:{path}~{program}", journal=journal)
            if events:
                if boot_origin is not None and (boot := _journal_boot(journal)) is not None:
                    for event in events:
                        event.fields["host.boot.id"] = fv(boot, boot_origin)
                return events
        if normalizer is normalize_syslog and not program and text_payload(src) is not None:
            # A custom syslog pipeline may retain the complete envelope instead of
            # indexed program/body fields. Only previously unsupported records reach here.
            try:
                return normalize_text(hit)
            except Skip:
                pass
        raise


def normalize_text(hit: dict) -> list[TypedEvent]:
    src = hit["_source"]
    path, line = text_payload(src)
    parsed = classify(line)
    if parsed.format == "unknown" and isinstance(program := _get(src, "process.name"), str):
        parsed = TextLine("syslog", program, line)
    dataset = document_dataset(src) or "(no dataset)"
    if parsed.format == "too_long":
        raise TextSkip(f"text line too long: {dataset}"[:256])
    if parsed.format == "unknown":
        raise TextSkip(f"text line in no recognized format: {dataset}"[:256])
    origin = f"{hit['_id']}:{path}~{parsed.format}"
    if parsed.format == "http_access":
        event = normalize_apache_access(hit, parsed_fields=parsed.fields, line_origin=origin)
    elif parsed.format == "web_error":
        event = normalize_apache_error(hit)
        event.fields["web.error_message"] = fv(parsed.message, origin)
    else:
        journal = {"SYSLOG_IDENTIFIER": parsed.program, "MESSAGE": parsed.message,
                   "_HOSTNAME": _get(src, "host.name"), **_indexed_writer_fields(src)}
        writer, writer_caveats = _new_writer_identity(parsed.program, journal)
        journal["SYSLOG_IDENTIFIER"] = writer
        try:
            if parsed.program in {"useradd", "groupadd"}:
                event = _syslog_account(hit, parsed.program, parsed.message, _get(src, "host.name"), origin)
            else:
                event = _journal_event(hit, journal, lambda _: origin, kind="text")
        except Skip as error:
            records = _program_events(hit, parsed.program, parsed.message, origin, journal=journal)
            if not records:
                reason = f"text format {parsed.format}, program {parsed.program!r} is not normalized: {dataset}"
                raise Skip(reason[:256]) from error
            for record in records:
                _text_provenance(record, parsed, origin)
            return records
        event.caveats.append(SYSLOG_WRITER_CAVEAT)
        event.caveats.extend(writer_caveats)
    _text_provenance(event, parsed, origin)
    return [event]


def _text_provenance(event: TypedEvent, parsed: TextLine, origin: str) -> None:
    if parsed.hostname not in (None, "-"):
        event.fields["log.syslog.hostname"] = fv(parsed.hostname, origin)
    event.fields["log.format"] = fv(parsed.format, origin)
    if parsed.timestamp not in (None, "-"):
        event.fields["log.inline_timestamp"] = fv(parsed.timestamp, origin)
        clock = inline_time(parsed.timestamp, event.ts)
        if clock is not None:
            seconds = int((clock.replace(microsecond=0) - event.ts.replace(microsecond=0)).total_seconds())
            event.fields["log.clock_offset_seconds"] = fv(seconds, origin + "+@timestamp")
            if seconds:
                event.caveats.append("Clock offset: inline log time differs from the pipeline timestamp; "
                                     "the pipeline timestamp is retained.")


def zeek_skip_families(names) -> frozenset[str]:
    """The event families the Zeek logs a skipped Zeek record names would feed, in any shipper's naming: empty for
    logs outside the catalog (their records are not assessed, and could hide no family a rule reads)."""
    return frozenset(log.family for name in names for shape in SHAPES
                     if (log := lookup_log(shape, name)) is not None)


def normalize_hits(hits: list[dict], boots: BootIntervals | None = None, *,
                   audit_parse: Callable[[dict, str], AuditRecord] | None = None,
                   rpc_remote_only: bool = False, contract=None,
                   malformed_text: dict[str, list[str]] | None = None,
                   skip_families: dict[str, frozenset[str] | None] | None = None,
                   surrogate_free: bool = False,
                   shapes: dict[str, int] | None = None,
                   ) -> tuple[list[TypedEvent], dict[str, int], list[tuple[str, str]]]:
    """Normalize a batch. Returns (events, skip_counts, errors[(raw_id, error)]). `audit_parse` is passed to
    `group_audit`.

    Linux host records are read by their shipper shape (`linux_catalog.LINUX_SHIPPER_DATASETS`); `shapes`, when
    given, receives the count of records of each shape, and errors name the logical dataset. A record that is plainly
    Linux host telemetry of a module we read but matches no shape is counted not normalized, with the families its
    logical dataset feeds. `shapes` also counts the EVE event types of Suricata records an Elastic shipper indexed
    without their line (`suricata.eve.elastic:<type>`), and NXLog's flat Windows records (`windows.nxlog`) with how
    far each zoneless EventTime is from the pipeline's @timestamp (`windows.nxlog.clock_offset:<zone>`).

    `skip_families`, when given, receives for each skip reason of a record no normalizer read the event families
    such records could have fed: the families of the Zeek log(s) a Zeek record names (empty for a log outside the
    catalog, which feeds none), or None when the reason's records could hold anything (a dataset no normalizer knows).

    A record holding a lone UTF-16 surrogate in any key or text is normalized with each one replaced by U+FFFD
    (evidence.surrogates), and every event made from it carries a caveat naming the fields; `malformed_text`, when
    given, receives each such record's key ("<index>/<id>") with those fields. The caller's hits are not changed.
    With `surrogate_free` (every hit came from a response `sources.es.surrogate_free` proved free) neither the hits
    nor their events can hold one, and neither is searched.

    An audit event's boot id (`host.boot.id`) comes from the shipper's own field, else from journald's copy of one
    of its records when that copy is in the same batch. With `boots` (a hunt's boot-interval map), the batch's boot
    observations are added to the map, and an audit event still without a boot id takes the boot the map places
    its audit header time in (an incremental placement, see `BootIntervals`). Otherwise it stays unknown: never
    guessed."""
    events, skips, errors = [], defaultdict(int), []
    windows_events: dict[tuple[tuple[str, str, str], str], TypedEvent] = {}
    windows_signatures: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    zeek_events: dict[str, TypedEvent] = {}           # by event id: a Zeek record's logical identity
    audit_hits = []
    # an Auditbeat document's records, with its event.action when they were rebuilt from its fields
    event_groups: list[tuple[tuple[str, float, int], list[tuple[dict, AuditRecord]], str | None]] = []
    audit_copies: list[tuple[tuple[str, int, int], str, str, str]] = []
    journal_boots: list[tuple[str, str, int | None, str, bool]] = []
    unclean: dict[str, list[str]] = {}
    for h in hits:
        clean, found = (h["_source"], ()) if surrogate_free else surrogates.sanitize(h["_source"])
        if found:
            h = {**h, "_source": clean}
            unclean[f"{h['_index']}/{h['_id']}"] = found
        ds = _get(h["_source"], "event.dataset") or ""
        try:
            if is_windows_source(h["_source"]):
                if is_nxlog_windows(h["_source"]):
                    # NXLog's flat record names no dataset: an error is counted under its channel's families
                    ds = nxlog_error_tag(h["_source"])
                    if shapes is not None:
                        for key in (NXLOG_SHAPE, nxlog_clock_offset(h["_source"])):
                            if key is not None:
                                shapes[key] = shapes.get(key, 0) + 1
                windows_event = normalize_windows(h)
                if rpc_remote_only and windows_event.family == "rpc_call" and (
                        windows_event.get("rpc.protocol") not in {"tcp", "named_pipe"}
                        or windows_event.get("rpc.interface_uuid") not in _RPC_INTERFACES):
                    # Keep at most this one typed event: local RPC never enters batch,
                    # deduplication, evidence staging or per-rule fold state.
                    skips[RPC_REMOTE_SCOPE_SKIP] += 1
                    continue
                logical_key = windows_record_key(h)
                signature = windows_record_signature(h)
                identity = (logical_key, signature) if logical_key is not None else None
                prior = windows_events.get(identity) if identity is not None else None
                if prior is None:
                    events.append(windows_event)
                    if identity is not None:
                        if windows_signatures[logical_key]:
                            skips["record_id reused (log cleared or reverted)"] += 1
                        windows_signatures[logical_key].add(signature)
                        windows_events[identity] = windows_event
                else:
                    known = {raw.key for raw in prior.raw}
                    prior.raw.extend(raw for raw in windows_event.raw if raw.key not in known)
                    skips["duplicate Windows event copy (computer/channel/record_id)"] += 1
            elif (zeek := (plain_record(h["_source"], contract.zeek_log)
                           if contract is not None and contract.zeek_sensor else zeek_record(h["_source"]))) is not None:
                # Malcolm's provider, Elastic's zeek.* dataset or Security Onion's module: before the Arkime shape,
                # because Malcolm adds Arkime's session fields (rootId among them) to the Zeek rows it indexes
                ds = zeek.token
                zeek_event = normalize_zeek(h, zeek, sensor=contract.zeek_sensor if contract is not None else None)
                prior = zeek_events.get(zeek_event.id)
                if prior is None:
                    zeek_events[zeek_event.id] = zeek_event
                    events.append(zeek_event)
                else:
                    known = {raw.key for raw in prior.raw}
                    prior.raw.extend(raw for raw in zeek_event.raw if raw.key not in known)
                    skips[ZEEK_DUPLICATE] += 1
            elif is_malcolm_suricata(h["_source"]):
                # before the Arkime shape: Malcolm adds Arkime's session fields to the Suricata rows it indexes
                events.append(normalize_malcolm_suricata(h))
            elif not ds and is_arkime_session(h["_source"]):
                ds = "arkime.session"
                events.append(normalize_arkime_session(h))
            elif (linux := match_shape(h["_source"])) is not None:
                ds, shape = linux[0], linux[1]
                if shapes is not None:
                    shapes[shape.key] = shapes.get(shape.key, 0) + 1
                if shape.shape == AUDIT_RECORD:
                    audit_hits.append(h)
                elif shape.shape == AUDIT_EVENT:
                    members = _auditbeat_group(h, errors)
                    if members:
                        first = members[0][1]
                        action = _get(h["_source"], "event.action") if first.reconstructed else None
                        event_groups.append(((audit_host(h["_source"], first), first.ts, first.serial), members,
                                             str(action) if first.reconstructed else None))
                elif shape.shape == JOURNAL_JSON:
                    events.extend(_linux_events(h, normalize_journal, journal_boots))
                elif shape.shape == JOURNAL_FIELDS:
                    events.extend(_linux_events(h, normalize_journal_fields, journal_boots))
                elif shape.shape == SYSLOG_LINE:
                    events.extend(_linux_events(h, normalize_syslog))
                elif shape.shape == APACHE_ACCESS:
                    events.append(normalize_apache_access(h))
                elif shape.shape == APACHE_ERROR:
                    events.append(normalize_apache_error(h))
            elif ds.startswith("suricata.eve") or _get(h["_source"], "data_stream.dataset") == ELASTIC_DATASET:
                ds = ds or ELASTIC_DATASET
                if shapes is not None and is_elastic_suricata(h["_source"]):
                    key = elastic_event_type_key(h["_source"])
                    shapes[key] = shapes.get(key, 0) + 1
                events.append(normalize_suricata(h))
            elif ds in SINGLE:
                events.append(SINGLE[ds](h))
            elif ((contract is None or (contract.role == "host" and contract.os_family == "linux"))
                  and unmatched_families(h["_source"]) is None
                  and text_candidate(h["_source"]) and not is_arkime_session(h["_source"])):
                ds = "linux.text"
                events.extend(normalize_text(h))
                if shapes is not None:
                    key = ("linux.text:" + (document_dataset(h["_source"]) or "(no dataset)"))[:256]
                    shapes[key] = shapes.get(key, 0) + 1
            else:
                reason = f"dataset:{ds or document_dataset(h['_source'])} is not normalized"
                skips[reason] += 1
                if skip_families is not None:
                    # Linux host telemetry of a module we read hides only its dataset's families; anything else
                    # could hold any behavior
                    fed = unmatched_families(h["_source"])
                    known = skip_families.get(reason, frozenset())
                    skip_families[reason] = None if fed is None or known is None else known | fed
        except AuditCopy as copy:
            skips[copy.reason] += 1
            found = _audit_copy_key(h, copy.record)
            if found is not None:
                audit_copies.append((*found, h["_id"]))
        except WindowsNotNormalized as unsupported:
            skips[unsupported.reason] += 1
            if skip_families is not None and unsupported.reason.startswith(NXLOG_CHANNEL_SKIP):
                known = skip_families.get(unsupported.reason, frozenset())
                fed = nxlog_class_families(h["_source"])
                skip_families[unsupported.reason] = None if known is None else known | fed
        except ZeekNotNormalized as uncatalogued:
            skips[uncatalogued.reason] += 1
            if skip_families is not None:
                fed = zeek_skip_families(zeek.names)
                known = skip_families.get(uncatalogued.reason, frozenset())
                skip_families[uncatalogued.reason] = None if known is None else known | fed
        except Skip as s:
            skips[s.reason] += 1
            if isinstance(s, TextSkip) and skip_families is not None:
                fed = TEXT_FAMILIES | (unmatched_families(h["_source"]) or frozenset())
                skip_families[s.reason] = (skip_families.get(s.reason) or frozenset()) | fed
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError) as e:   # malformed: an error, not a crash
            errors.append((h["_id"], f"{ds}: {e}"))
    superseded = superseded_interim(list(zeek_events.values())) if zeek_events else []
    if superseded:
        dropped = {id(event) for event in superseded}
        events = [event for event in events if id(event) not in dropped]
        skips[ZEEK_INTERIM_SUPERSEDED] += len(superseded)
    groups, audit_errors = group_audit(audit_hits, audit_parse)
    errors.extend(audit_errors)
    partners = _boot_partners(audit_copies)
    audit_start, boot_by_hit = len(events), {}
    # an Auditbeat document is one event of its own: never merged with another document's records
    for (host, ts, serial), members, action in [*((key, members, None) for key, members in groups.items()),
                                                *event_groups]:
        boot = _partner_boot(partners, host, ts, serial, members) if partners else {}
        if boot:
            boot_by_hit.update({hit["_id"]: boot for hit, _record in members})
        start, failed = len(events), len(errors)
        noded = any(audit_node(hit["_source"], record) for hit, record in members)
        # an Auditbeat action outside the table that gives no event is counted by its action
        unlisted = action is not None and action not in AUDITBEAT_ACTIONS
        group_skips: dict[str, int] = defaultdict(int) if unlisted else skips
        _audit_group(host, members, events, group_skips, errors)
        if unlisted:
            if len(events) == start and len(errors) == failed:
                skips[f"auditbeat action {action} is not normalized"] += 1
            else:
                for reason, count in group_skips.items():
                    skips[reason] += count
        if noded:
            for event in events[start:]:
                _audit_node_fields(event, members)
        if any(record.reconstructed for _hit, record in members):
            for event in events[start:]:
                _rebuilt_provenance(event, members)
        if len({hit["_id"] for hit, _record in members}) < len(members):
            for event in events[start:]:
                # one document held several of the event's records: cite it once
                event.raw[:] = list({ref.key: ref for ref in event.raw}.values())
    # Every audit event cites records of its own group only, so its first record names the group.
    for event in events[audit_start:]:
        boot = boot_by_hit.get(event.raw[0].native_id) if event.raw else None
        if boot and not event.has("host.boot.id"):
            event.fields.update(boot)
    if boots is not None:
        for host, boot, when, ref, banner in journal_boots:
            if when is None:
                boots.observe_unclocked(host)
            else:
                boots.observe(host, boot, when, ref, banner)
        for event in events[audit_start:]:
            boots.observe_event(event)
        boots.fill(events[audit_start:], incremental=True)
    # Native host addresses support the same unique-owner mapping that host pivots use. A network
    # sensor's host.ip names its observer and is never a traffic endpoint.
    native_hosts = {hit["_id"]: hit for hit in hits if _get(hit.get("_source", {}), "host.ip")}
    for event in events:
        if event.family in {"net_alert", "net_flow", "net_session", "dns_query", "http_tx", "tls_session",
                            "ssh_session", "file_transfer"} or event.normalizer != NORMALIZER_VERSION:
            continue
        for ref in event.raw:
            hit = native_hosts.get(ref.native_id)
            if hit is not None:
                event.fields["host.ip"] = fv(_get(hit["_source"], "host.ip"), f"{ref.native_id}:host.ip")
                break
    for index, event in enumerate(() if surrogate_free else events):
        # text parsed out of a record's own text (a Suricata EVE line, a Zeek line) can hold a lone surrogate its
        # record did not show
        parsed = surrogates.event_paths(event)
        paths = [path for ref in event.raw for path in unclean.get(ref.key, ())] if unclean else []
        if parsed:
            events[index] = surrogates.clean_event(event, paths + parsed)
            for ref in event.raw:
                unclean.setdefault(ref.key, []).extend(parsed)
        elif paths:
            note = surrogates.caveat(paths)
            if note not in event.caveats:
                event.caveats.append(note)
    if unclean and malformed_text is not None:
        malformed_text.update(unclean)
    return events, dict(skips), errors
