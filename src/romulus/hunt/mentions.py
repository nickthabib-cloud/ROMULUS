"""The mention sweep: curated patterns over the raw text of records no normalizer read.

The sweep hands each partition's unread records (`normalize_hits(unread=...)`: records of a dataset or event class no
normalizer reads, text in no recognized format or too long to parse, records a normalizer failed on, Windows records
on a network target, and the fields of audit records no typed event reads; never a duplicate copy of a normalized
record), and the records outside the sweep's own selection (`hunt.mention_residue`), to `MentionScanner.scan`. The
scanner never reads a serialized record: it reads a bounded, documented selection of each record's free-text fields
by the record's family (`hunt.mention_fields`: message lines, command lines, script blocks, URLs, user agents,
queries, file paths, a journal record's MESSAGE and _CMDLINE, an audit record's decoded proctitle, cmd and exe), each
field as its own text. A record of no catalogued family, and a record with no text field, is counted as not scanned;
a record of a family whose selection is only part of its fields is counted as scanned in part. Every one of the
hunt's patterns runs over every text; a pattern's telemetry classes only rank a match on a class the pattern names
above one on another class of the same strength.

Each matching record is grouped once, under the strongest pattern any of its texts matches (the others it matches are
kept on the group as labelled metadata), by (pattern, host, normalized text of the field that pattern matched) in a private SQLite stage under the hunt's stage
directory. The stage is a yielding store of the hunt's state budget: its bytes are in the physical ledger, and when a
detection store needs room the budget reclaims them (first the weakest groups' kept records, then the weakest groups),
so detection never refuses a key while the pool holds bytes it can give back. A group keeps its count, first and last
time, its first record as the citation (cleaned, redacted and bounded the way the raw-record path keeps a record,
`evidence.raw_citation`) and a redacted excerpt of the line around the first match.

The pool is bounded per pattern, per host and per hunt. A group past a cap is not kept; its lines are still counted
under its pattern and host, so every remainder is exact. At the host and hunt caps a stronger pattern's new group
takes the place of a weaker one, and at a pattern's cap a host the pattern has no group on yet takes the place of one
of the groups of the host the pattern has most groups on, so a rare later host is never lost to a busy early one.
Every (pattern, host) that lost lines is published with its count and can be paged.

The pool's coverage says what was and was not scanned: a partition the sweep could not read in full, a record without
a text field, a line past the literal pass's bound, a line an anchored pattern could not be ruled out on, a source the
sweep's fetch filters leave out, a cap, a stage write refused, a refused pattern or pattern file, a changed pattern
file, a scan that failed, a
stop. Any of them makes the pool `partial`; with none it `scanned every offered record`, which never means that there
are no mentions. With no patterns loaded the pool is `not_scanned`.

At the end of the sweep the pool is ranked (pattern strength, then whether the record's telemetry class is one the
pattern names, then rarity: the pattern's distinct hosts and then its matching lines, fewest first; then first time).
Strength only orders the pool: a weak mention is in the same lane as a strong one, never context. The pool is
published in one transaction that replaces the hunt's earlier pool, so a sweep run again on resume leaves one pool.

The line bound: the literal pass (gate and automaton) reads a line up to MAX_SCAN_CHARS characters (256 KiB of text),
and each anchored expression at most 512 characters from where it is tried, at most four places per line. Python's
`re` is a backtracking engine, so the window and the loader's rules are what keep a hostile line from costing
seconds; the rest of a longer line is counted as not scanned, with the hosts and records it came from.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from romulus.agent.safety import injection_flags
from romulus.config import redact_counted
from romulus.content.mention_patterns import REFUSED_SHOWN, PatternSet
from romulus.evidence.mention_match import (
    MAX_PREFIX_TRIES,
    MAX_SCAN_CHARS,
    REGEX_WINDOW,
    TRIES_EXHAUSTED,
    WINDOW_CUT,
    MentionMatcher,
    bound_text,
    line_digest,
)
from romulus.evidence.mentions import (
    LINUX_TEXT,
    MENTION_LABEL,
    MENTION_LANE,
    OTHER_TEXT,
    STRENGTH_RANK,
    WINDOWS_TEXT,
)
from romulus.evidence.raw_citation import build_raw_record, raw_record_id, record_time
from romulus.evidence.raw_scrub import clean_source
from romulus.evidence.windows import is_windows_source
from romulus.hunt.mention_fields import (  # noqa: F401 - the reasons are part of this module's coverage vocabulary
    CATALOGUED_FAMILIES,
    JSON_ARRAY,
    JSON_RECORD,
    NO_TEXT,
    XML_RECORD,
    scrub_source,
    select_texts,
)
from romulus.sources.compile import time_unit
from romulus.store.db import digest

STAGE_PREFIX = "romulus-stage-"         # the event stage's prefix: a killed process's leftover is cleared the same way
MENTION_ORIGIN = "mention_sweep"
# the pool's status when nothing offered was left unscanned (never a statement that there are no mentions)
SCANNED_ALL = "scanned_every_offered_record"
SCANNED_ALL_TEXT = "scanned every offered record"
# the pool's bounds (groups of identical (pattern, host, normalized line)); every match past them is still counted
MAX_GROUPS_PER_PATTERN = 2_000
MAX_GROUPS_PER_HOST = 2_000
MAX_GROUPS_PER_HUNT = 20_000
# the excerpt kept on a mention, around its first match (the whole record is kept, bounded, on its raw record)
MAX_LINE_CHARS = 1_024
EXCERPT_BEFORE = 256
# The keys of groups past a cap that the stage remembers (so their later lines are counted under the same group), and
# the (pattern, host) pairs it counts lines for. Past either bound, and while the hunt's state budget asks the pool to
# give way, every line is still counted exactly; only the number of distinct groups not kept becomes a lower bound,
# and a pattern's distinct hosts (its rarity) a lower bound too.
MAX_GONE_KEYS = 200_000
MAX_SEEN_PAIRS = 1_000_000
MAX_HOST_CHARS = 255
# refused patterns and files named one by one among the coverage reasons (the rest are counted in one reason)
REFUSALS_NAMED = 20
# names listed in the coverage summary (the counts cover all; the stored losses page through every host)
NAMES_SHOWN = 20
# partitions the sweep could not read in full, listed by name (every one is counted)
NOTES_SHOWN = 200
# hosts whose cut lines are counted by name (the rest are counted together)
CUT_HOSTS_COUNTED = 1_000
# typed events the normalizer made from a mention's cited record, kept on the mention (the finding link reads them)
MAX_LINKED_EVENTS = 8
# keys of a target's records outside the sweep's selection, not read in full, named in the coverage (all counted)
RESIDUE_KEYS_NAMED = 50
# distinct (family, field) names counted for the coverage summary
MAX_FIELD_KEYS = 512
NO_HOST = ""
_HOST_FIELDS = ("host.name", "host.hostname", "agent.hostname", "computer_name", "winlog.computer_name", "Hostname")
# a group whose kept record or whose whole entry the budget reclaimed for a detection store
DISK_RECLAIMED = "disk_reclaimed_for_detection"
RECLAIMED_TEXT = ("the record's text was released to give disk to detection; the source keeps the whole record "
                  "under this reference")
RECLAIM_BATCH = 200
# the host of a loss row that counts the (pattern, host) pairs past the remembered-pair bound together
PAST_PAIR_BOUND = "(further hosts past the remembered-pair bound, counted together)"


def _field(source: dict, name: str):
    if name in source:
        return source[name]
    node = source
    for part in name.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def record_host(source: dict) -> str:
    for name in _HOST_FIELDS:
        value = _field(source, name)
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if isinstance(value, str) and value.strip():
            return value.strip()[:MAX_HOST_CHARS]
    return NO_HOST


def telemetry_class(source: dict, contract, windows: bool | None = None) -> str:
    """A Windows event record's rendered text, other host text, or a network record's text. `windows`: whether the
    record is a Windows event record, when the normalizer already said so."""
    if windows if windows is not None else is_windows_source(source):
        return WINDOWS_TEXT
    if contract is None or getattr(contract, "role", "host") == "host":
        return LINUX_TEXT
    return OTHER_TEXT


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return value.isoformat()


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class MentionScanner:
    def __init__(self, hunt_id: str, patterns: PatternSet, *, stage_dir=None, budget=None, settings=None,
                 window: tuple[datetime, datetime] | None = None, pinned: dict | None = None,
                 max_per_pattern: int = MAX_GROUPS_PER_PATTERN, max_per_host: int = MAX_GROUPS_PER_HOST,
                 max_per_hunt: int = MAX_GROUPS_PER_HUNT):
        self.hunt_id = hunt_id
        self.patterns = patterns
        self.settings = settings
        self.window = window
        self.stage_dir = stage_dir
        self.budget = budget
        # a store no detection reads: it gives way before any detection store refuses a key, has no floor, and gives
        # its bytes back when a detection store needs them (`_reclaim`)
        self.account = budget.account("mention_pool", yields=True) if budget is not None else None
        if self.account is not None:
            self.account.evict = self._reclaim
            self.account.reclaim_database = lambda: (self.db, Path(self._dir) / "mentions.db" if self._dir else None)
        self.max_per_pattern, self.max_per_host, self.max_per_hunt = max_per_pattern, max_per_host, max_per_hunt
        self._matcher: MentionMatcher | None = (MentionMatcher(patterns.compiled) if patterns.compiled
                                                else None)
        self._dir: str | None = None
        self.db: sqlite3.Connection | None = None
        self._size = 0
        self._groups = 0
        self._seq = 0
        self.stats = Counter()
        self.by_telemetry: Counter = Counter()
        self.not_scanned: Counter = Counter()      # records without scannable text, by reason
        self.in_part: Counter = Counter()          # records of which only part of the fields were scanned, by reason
        self.no_free_text: Counter = Counter()     # records of a catalogued family holding none of its text fields
        self.by_field: Counter = Counter()         # texts scanned, by family and field
        self.caps: dict[str, Counter] = {"per_pattern": Counter(), "per_host": Counter(), "per_hunt": Counter(),
                                         "stage": Counter(), DISK_RECLAIMED: Counter()}
        self.unscanned: list[dict] = []            # partitions the sweep could not read in full (the first NOTES_SHOWN)
        self.unscanned_count = 0
        self.left_out: list[dict] = []             # sources the sweep's fetch filters leave out
        self.residue: dict[str, dict] = {}         # per target: its records outside the sweep's selection
        self.cut_hosts: Counter = Counter()
        self.cut_records: list[dict] = []
        self.pin_changes: list[str] = []
        self.stage_error = ""
        self._gone = 0
        self._seen = 0
        self._overflow: Counter = Counter()      # (pattern index, "lines" | "lost") past the pair bound
        self.lower_bound = False                 # some distinct groups not kept were not remembered
        self._broken = False                     # the stage failed: later matches are counted, never kept
        self.publish_error = ""
        self.stage_refusal = ""
        self.stopped = ""
        self._compare_pin(pinned)

    def _compare_pin(self, pinned: dict | None) -> None:
        """Name every pattern file that differs from the set pinned when the hunt was created."""
        if not pinned:
            return
        now = {item["name"]: item["digest"] for item in self.patterns.files}
        then = {item["name"]: item["digest"] for item in pinned.get("files") or []}
        for name in sorted(set(now) | set(then)):
            if now.get(name) != then.get(name):
                state = "added" if name not in then else "removed or refused" if name not in now else "changed"
                self.pin_changes.append(f"{name} ({state})")

    # ---- matching -------------------------------------------------------------------------------------------------
    def _fits(self, index: int, telemetry: str) -> bool:
        """Whether the record's telemetry class is one the pattern names (a ranking hint only)."""
        named = self.patterns.patterns[index].telemetry
        return "any" in named or telemetry in named

    def _redact_text(self, text: str) -> str:
        return redact_counted(text, self.settings, None) if self.settings is not None else text

    def _redact(self, value):
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        return value

    def note_unscanned(self, target: str, partition: str, reason: str) -> None:
        """A partition the sweep could not read in full (failed, capped and not splittable, or partial): its records
        were not all offered to the scan."""
        self.unscanned_count += 1
        if len(self.unscanned) < NOTES_SHOWN:
            self.unscanned.append({"target": target, "partition": partition, "reason": str(reason)[:300]})

    def note_left_out(self, target: str, kind: str, name: str, records, reason: str) -> None:
        """A source of the target the sweep's fetch filters leave out, so its records are never offered to the scan."""
        self.left_out.append({"target": target, "kind": kind, "name": str(name)[:200], "records": records,
                              "reason": reason})

    def note_residue(self, target: str, *, records: int | None, read: int, counted: bool, reason: str = "",
                     short_keys=(), drift: str = "") -> None:
        """A target's records outside the sweep's selection (`hunt.mention_residue`): how many (None: not counted
        exactly), how many were read into the scan, the keys not read in full, and how the source changed between
        the count and the read (`drift`, which makes the pool partial however many were read)."""
        short = list(short_keys)
        self.residue[target] = {"records": records, "read": read, "counted": counted, "reason": reason,
                                "drift": drift,
                                "keys_not_read_in_full": len(short),
                                "keys": [{**item, "not_read": item["records"] - item["read"]}
                                         for item in sorted(short, key=lambda item: item["read"] - item["records"])
                                         [:RESIDUE_KEYS_NAMED]]}

    def residue_counted(self, target: str) -> bool:
        """Whether the target's records outside the sweep's selection were counted exactly (each then read, or
        counted as not read): the sweep's left-out sources of that target are what was counted."""
        return bool((self.residue.get(target) or {}).get("counted"))

    def note_scan_failure(self, target: str, partition: str, error: BaseException) -> None:
        """The scan raised on a partition: the partition's detection goes on, and the pool says what was not scanned."""
        self.stats["scan_failures"] += 1
        self.note_unscanned(target, partition, f"the scan failed ({type(error).__name__}: {error})"[:300])

    def scan(self, target: str, contract, unread: list[tuple], task_id: str | None, *,
             residue: bool = False) -> None:
        """Scan one partition's unread records: (hit, why no normalizer read it[, whether it is a Windows event
        record[, the audit fields to read]]) as `normalize_hits(unread=...)` lists them. `residue`: the records are
        outside the sweep's selection (`hunt.mention_residue`)."""
        if not unread:
            return
        stats = self.stats
        stats["records_offered"] += len(unread)
        if residue:
            stats["residue_offered"] += len(unread)
        for entry in unread:
            hit = entry[0]
            source = hit.get("_source")
            if not isinstance(source, dict):
                self.not_scanned[NO_TEXT] += 1
                continue
            windows = entry[2] if len(entry) > 2 and entry[2] is not None else is_windows_source(source)
            # the record as it may be stored: credentials of recognized network records masked (a Zeek or EVE line
            # in its text field included, whatever recognized it), lone surrogates replaced; the excerpt is cut from
            # what is scanned, and the kept record is this one
            cleaned = clean_source(source)
            source = scrub_source(cleaned)
            # the citation's digest is of the cleaned record, as every stored raw record's is; its kept text is of
            # the scrubbed one
            hit = {**hit, "_source": cleaned}
            selection = select_texts(source, windows=windows, only=entry[3] if len(entry) > 3 else None)
            if not selection.texts:
                if selection.no_text:
                    # a record of a catalogued family holding none of its free-text fields: nothing to scan
                    self.no_free_text[selection.family] += 1
                elif selection.family in CATALOGUED_FAMILIES:
                    # read by its family, with part of it deliberately or past a bound unread (a packet payload)
                    self.in_part[selection.reason] += 1
                else:
                    self.not_scanned[selection.reason] += 1
                continue
            if not selection.complete:
                self.in_part[selection.reason] += 1
            matcher = self._matcher
            if matcher is None:
                stats["no_patterns"] += 1
                continue
            telemetry = telemetry_class(source, contract, windows)
            stats["records_scanned"] += 1
            self.by_telemetry[telemetry] += 1
            # the scan bound holds for a record's texts together; each text is matched on its own
            room, past_total = MAX_SCAN_CHARS, 0
            found: dict[int, tuple[int, int]] = {}            # pattern index -> (text index, offset)
            texts: list[tuple[str, str]] = []
            for path, payload in selection.texts:
                if room <= 0:
                    past_total += len(payload)
                    continue
                text, past = bound_text(payload) if len(payload) <= room else (payload[:room], len(payload) - room)
                room -= len(text)
                past_total += past
                stats["lines_scanned"] += 1
                self._count_field(selection.family, path)
                unresolved: set[str] = set()
                located = matcher.locate(text, cut=bool(past), unresolved=unresolved)
                for note in unresolved:
                    stats["lines_" + note] += 1
                for index, offset in located.items():
                    found.setdefault(index, (len(texts), offset))
                texts.append((path, text))
            if past_total:
                self._note_cut(hit, source, past_total)
            if not found:
                continue
            stats["lines_matched"] += 1
            if self._broken:
                stats["lines_not_staged"] += 1
                continue
            try:
                self._keep(target, contract, hit, texts, found, task_id, telemetry, residue, source,
                           entry[4] if len(entry) > 4 else ())
            except (sqlite3.Error, OSError) as error:
                # the stage itself failed: this line and every later match are counted, never kept
                self._fail(f"the mention stage failed ({type(error).__name__}: {error})"[:300])
                stats["lines_not_staged"] += 1
        if self.db is not None and not self._broken:
            try:
                self.db.commit()
                self._charge()
            except (sqlite3.Error, OSError) as error:
                self._fail(f"the mention stage failed ({type(error).__name__}: {error})"[:300])

    def _count_field(self, family: str, path: str) -> None:
        """Texts scanned by family and field (the field names come from fixed tables, so the counter is bounded)."""
        key = f"{family}:{path}"[:160]
        if key in self.by_field or len(self.by_field) < MAX_FIELD_KEYS:
            self.by_field[key] += 1
        else:
            self.by_field["(other fields)"] += 1

    def _note_cut(self, hit: dict, source: dict, past: int) -> None:
        self.stats["lines_cut"] += 1
        self.stats["chars_not_scanned"] += past
        host = record_host(source) or "(no host)"
        if host in self.cut_hosts or len(self.cut_hosts) < CUT_HOSTS_COUNTED:
            self.cut_hosts[host] += 1
        else:
            self.stats["cut_lines_on_other_hosts"] += 1
        if len(self.cut_records) < NAMES_SHOWN:
            self.cut_records.append({"target": hit.get("_index"), "native_id": hit.get("_id"), "host": host,
                                     "chars": MAX_SCAN_CHARS + past})

    def _fail(self, reason: str) -> None:
        self._broken = True
        self.stage_error = self.stage_error or reason

    # ---- the stage ------------------------------------------------------------------------------------------------
    def _open(self) -> sqlite3.Connection:
        if self.db is None:
            if self.stage_dir is not None:
                Path(self.stage_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
            self._dir = tempfile.mkdtemp(prefix=STAGE_PREFIX + "mentions-", dir=self.stage_dir)
            db = sqlite3.connect(Path(self._dir) / "mentions.db")
            # set before any table: freed pages can be given back to the volume (`_reclaim`)
            db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            db.execute("PRAGMA journal_mode=MEMORY")
            db.execute("PRAGMA synchronous=OFF")
            db.execute("CREATE TABLE grp (key TEXT PRIMARY KEY, pattern INTEGER NOT NULL, host TEXT NOT NULL, "
                       "strength INTEGER NOT NULL, n INTEGER NOT NULL, first_ts TEXT, last_ts TEXT, "
                       "seq INTEGER NOT NULL, telemetry TEXT NOT NULL, fit INTEGER NOT NULL, raw TEXT NOT NULL, "
                       "raw_kept INTEGER NOT NULL DEFAULT 1, line TEXT NOT NULL, line_offset INTEGER NOT NULL, "
                       "match_offset INTEGER NOT NULL, line_chars INTEGER NOT NULL, line_cut INTEGER NOT NULL, "
                       "suspicious INTEGER NOT NULL, others TEXT NOT NULL, events TEXT NOT NULL DEFAULT '[]')")
            db.execute("CREATE INDEX grp_weak ON grp (strength, pattern, seq)")
            db.execute("CREATE INDEX grp_host ON grp (host, strength, seq)")
            db.execute("CREATE INDEX grp_pattern_host ON grp (pattern, host)")
            db.execute("CREATE INDEX grp_reclaim ON grp (raw_kept, strength, seq)")
            db.execute("CREATE TABLE gone (key TEXT PRIMARY KEY, pattern INTEGER NOT NULL, host TEXT NOT NULL) "
                       "WITHOUT ROWID")
            db.execute("CREATE TABLE host (host TEXT PRIMARY KEY, kept INTEGER NOT NULL) WITHOUT ROWID")
            # every matching line by pattern and host, kept or not: rarity and exact remainders
            db.execute("CREATE TABLE seen (pattern INTEGER NOT NULL, host TEXT NOT NULL, lines INTEGER NOT NULL, "
                       "lost INTEGER NOT NULL, PRIMARY KEY (pattern, host)) WITHOUT ROWID")
            db.execute("CREATE TABLE pat (pattern INTEGER PRIMARY KEY, kept INTEGER NOT NULL)")
            self.db = db
            self._page = db.execute("PRAGMA page_size").fetchone()[0]
        return self.db

    def _charge(self) -> None:
        """Charge the stage file's growth (or release its shrinkage) to the pool's account, on disk as in the ledger
        every store's physical writes are capped against. The new size is recorded before the budget is told, since
        the budget may at once ask the pool to give bytes back (`_reclaim`)."""
        if self.db is None or self.budget is None or self.account is None:
            return
        size = self.db.execute("PRAGMA page_count").fetchone()[0] * self._page
        delta = size - self._size
        if delta:
            self._size = size
            self._account(delta)

    def _account(self, delta: int) -> None:
        self.budget.charge(self.account, delta)
        self.budget.physical_account(self.account, delta)
        if delta > 0:
            self.budget.grew(delta)
        else:
            self.budget._physical_released += -delta

    def _refusal(self) -> str:
        """Why the stage may take no new row now ("" while it may)."""
        if self.budget is None or self.account is None:
            return ""
        return self.budget.new_key_reason(self.account)

    def _reclaim(self, needed: int) -> int:
        """Give disk back to the detection stores: first the weakest groups' kept records (their mentions keep the
        source reference and the excerpt), then the weakest groups themselves. Both are counted as not kept, with the
        reason. Returns the bytes freed."""
        db = self.db
        if db is None or self._broken or needed <= 0:
            return 0
        freed = 0
        try:
            db.commit()
            for phase in ("records", "groups"):
                while freed < needed:
                    if phase == "records":
                        rows = db.execute("SELECT key, raw FROM grp WHERE raw_kept = 1 ORDER BY strength, seq DESC "
                                          "LIMIT ?", (RECLAIM_BATCH,)).fetchall()
                        if not rows:
                            break
                        for key, raw in rows:
                            record = json.loads(raw)
                            record.update(text=RECLAIMED_TEXT, text_cut=True)
                            db.execute("UPDATE grp SET raw = ?, raw_kept = 0 WHERE key = ?",
                                       (json.dumps(record, ensure_ascii=False, default=str), key))
                        self.stats["records_reclaimed"] += len(rows)
                    else:
                        rows = db.execute("SELECT key FROM grp ORDER BY strength, seq DESC LIMIT ?",
                                          (RECLAIM_BATCH,)).fetchall()
                        if not rows:
                            break
                        for (key,) in rows:
                            self._drop(db, key, DISK_RECLAIMED)
                    db.commit()
                    db.execute("PRAGMA incremental_vacuum").fetchall()
                    size = db.execute("PRAGMA page_count").fetchone()[0] * self._page
                    if size < self._size:
                        freed += self._size - size
                        shrink = size - self._size
                        self._size = size
                        self._account(shrink)
                if freed >= needed:
                    break
        except (sqlite3.Error, OSError) as error:
            self._fail(f"the mention stage failed while giving disk back ({type(error).__name__}: {error})"[:300])
        return freed

    def touch(self) -> None:
        """Mark the stage live, so another hunt's stale-stage cleanup never removes it."""
        if self._dir is not None:
            with contextlib.suppress(OSError):
                os.utime(self._dir)

    def close(self) -> None:
        if self.db is not None:
            with contextlib.suppress(sqlite3.Error):
                self.db.close()
            self.db = None
            if self.budget is not None and self.account is not None:
                self.budget.release_physical_account(self.account)
            self._size = 0
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None

    def _count_line(self, db, pattern: int, host: str, lost: bool) -> None:
        """Count one matching line under its pattern and host, exactly, whatever the bounds."""
        if db.execute("UPDATE seen SET lines = lines + 1, lost = lost + ? WHERE pattern = ? AND host = ?",
                      (int(lost), pattern, host)).rowcount:
            return
        if self._seen < MAX_SEEN_PAIRS and not self._refusal():
            db.execute("INSERT INTO seen VALUES (?, ?, 1, ?)", (pattern, host, int(lost)))
            self._seen += 1
            return
        self._overflow[(pattern, "lines")] += 1
        self._overflow[(pattern, "lost")] += int(lost)

    def _remember(self, db, key: str, pattern: int, host: str) -> bool:
        """Remember a group that is not kept, while the bound allows; False once it does not (a lower bound)."""
        if self._gone < MAX_GONE_KEYS and not self._refusal():
            if db.execute("INSERT OR IGNORE INTO gone VALUES (?, ?, ?)", (key, pattern, host)).rowcount:
                self._gone += 1
            return True
        self.lower_bound = True
        return False

    def _lose(self, db, key: str, pattern: int, host: str, cap: str) -> None:
        """A new group past a cap: not kept, its key remembered (while the bound allows) so its later lines count
        as not kept too."""
        if self._remember(db, key, pattern, host):
            self.caps[cap][self.patterns.patterns[pattern].id] += 1
        self._count_line(db, pattern, host, True)

    def _drop(self, db, key: str, cap: str) -> None:
        """Take a kept group out of the pool: its lines become not kept, under its pattern and host."""
        row = db.execute("SELECT pattern, host, n FROM grp WHERE key = ?", (key,)).fetchone()
        if row is None:
            return
        pattern, host, lines = row
        db.execute("DELETE FROM grp WHERE key = ?", (key,))
        self._remember(db, key, pattern, host)
        if not db.execute("UPDATE seen SET lost = lost + ? WHERE pattern = ? AND host = ?",
                          (lines, pattern, host)).rowcount:
            # its (pattern, host) was counted past the pair bound: its lost lines are counted there too
            self._overflow[(pattern, "lost")] += lines
        db.execute("UPDATE host SET kept = kept - 1 WHERE host = ?", (host,))
        db.execute("UPDATE pat SET kept = kept - 1 WHERE pattern = ?", (pattern,))
        self._groups -= 1
        self.caps[cap][self.patterns.patterns[pattern].id] += 1
        self.stats["groups_dropped"] += 1

    def _evict(self, db, where: str, params: tuple, strength: int, cap: str) -> bool:
        """Drop the weakest kept group under `where` when it is weaker than `strength`: its lines become not kept."""
        victim = db.execute(f"SELECT key FROM grp WHERE {where} AND strength < ? ORDER BY strength, seq DESC LIMIT 1",
                            (*params, strength)).fetchone()
        if victim is None:
            return False
        self._drop(db, victim[0], cap)
        self.stats["groups_evicted"] += 1
        return True

    def _make_room_on_pattern(self, db, pattern: int, host: str) -> bool:
        """At a pattern's cap, a host the pattern has no group on takes the place of one group of the host the pattern
        has most groups on (when that host has more than one): a rare host is never lost to a busy one."""
        if db.execute("SELECT 1 FROM grp WHERE pattern = ? AND host = ? LIMIT 1", (pattern, host)).fetchone():
            return False
        busiest = db.execute("SELECT host, count(*) FROM grp WHERE pattern = ? GROUP BY host ORDER BY 2 DESC, host "
                             "LIMIT 1", (pattern,)).fetchone()
        if busiest is None or busiest[1] < 2:
            return False
        victim = db.execute("SELECT key FROM grp WHERE pattern = ? AND host = ? ORDER BY seq DESC LIMIT 1",
                            (pattern, busiest[0])).fetchone()
        self._drop(db, victim[0], "per_pattern")
        self.stats["groups_evicted"] += 1
        return True

    def _excerpt(self, text: str, offset: int) -> tuple[str, int, int, int]:
        """(the redacted excerpt around the match, where it starts in the line, where the match starts in it, the
        redacted line's length). Redaction runs on the whole line; the offset follows what it removed before it."""
        line = self._redact_text(text)
        if line != text:
            offset = min(len(line), len(self._redact_text(text[:offset])))
        start = max(0, offset - EXCERPT_BEFORE)
        excerpt = line[start:start + MAX_LINE_CHARS]
        return excerpt, start, offset - start, len(line)

    def _keep(self, target: str, contract, hit: dict, texts: list[tuple[str, str]],
              found: dict[int, tuple[int, int]], task_id: str | None, telemetry: str, residue: bool = False,
              kept: dict | None = None, linked=()) -> None:
        db = self._open()
        host = record_host(hit["_source"])
        # one group per record, under its strongest pattern (the earliest loaded among equals); the rest are metadata.
        # The group's line is the text of the field that pattern matched.
        patterns = self.patterns.patterns
        ordered = sorted(found, key=lambda i: (-STRENGTH_RANK[patterns[i].strength],
                                               not self._fits(i, telemetry), i))
        index, others = ordered[0], json.dumps(ordered[1:])
        path, text = texts[found[index][0]]
        normalized = line_digest(text)
        pattern = patterns[index]
        key = hashlib.sha256(json.dumps([pattern.id, host, normalized]).encode()).hexdigest()[:32]
        ts, _text = record_time(hit["_source"], getattr(contract, "time_field", None),
                                unit=time_unit(contract) if contract is not None else "ms", window=self.window)
        ts_text = _iso(ts)
        if db.execute("UPDATE grp SET n = n + 1, first_ts = CASE WHEN first_ts IS NULL OR "
                      "(? IS NOT NULL AND ? < first_ts) THEN coalesce(?, first_ts) ELSE first_ts END, "
                      "last_ts = CASE WHEN last_ts IS NULL OR (? IS NOT NULL AND ? > last_ts) "
                      "THEN coalesce(?, last_ts) ELSE last_ts END WHERE key = ?",
                      (ts_text, ts_text, ts_text, ts_text, ts_text, ts_text, key)).rowcount:
            self._count_line(db, index, host, False)
            return
        if db.execute("SELECT 1 FROM gone WHERE key = ?", (key,)).fetchone() is not None:
            self._count_line(db, index, host, True)
            return
        strength = STRENGTH_RANK[pattern.strength]
        kept_pattern = (db.execute("SELECT kept FROM pat WHERE pattern = ?", (index,)).fetchone() or (0,))[0]
        kept_host = (db.execute("SELECT kept FROM host WHERE host = ?", (host,)).fetchone() or (0,))[0]
        # At a pattern's cap a place is made for a rare host only when nothing else would refuse the new group: the
        # host's cap and the budget are checked first (taking one of the pattern's groups keeps the hunt's count where
        # it is), so no group is dropped for a line that is then not kept either.
        if kept_pattern >= self.max_per_pattern and (kept_host >= self.max_per_host or self._refusal()
                                                     or not self._make_room_on_pattern(db, index, host)):
            self._lose(db, key, index, host, "per_pattern")
            return
        if kept_host >= self.max_per_host and not self._evict(db, "host = ?", (host,), strength, "per_host"):
            self._lose(db, key, index, host, "per_host")
            return
        if self._groups >= self.max_per_hunt and not self._evict(db, "1 = 1", (), strength, "per_hunt"):
            self._lose(db, key, index, host, "per_hunt")
            return
        if refusal := self._refusal():
            # the hunt's state budget asks the pool to give way: new groups are counted, not kept
            self.stage_refusal = self.stage_refusal or refusal
            self._lose(db, key, index, host, "stage")
            return
        raw = build_raw_record(
            self.hunt_id, hit, source_kind="index", time_field=getattr(contract, "time_field", None),
            session_id=None, task_id=task_id,
            query_digest="mention:" + digest({"pattern": pattern.id, "task": task_id})[:24],
            query_text=(f"mention sweep: pattern {pattern.id} matched the record's {path} in the deterministic "
                        + (f"read of {target}'s records outside the sweep's selection" if residue
                           else f"sweep of {target}")),
            redact=self._redact, flagged=injection_flags, kept_source=kept,
            time_unit=time_unit(contract) if contract is not None else "ms", window=self.window)
        raw["ts"] = _iso(raw["ts"])
        excerpt, line_offset, match_offset, line_chars = self._excerpt(text, found[index][1])
        self._seq += 1
        try:
            db.execute("INSERT INTO grp (key, pattern, host, strength, n, first_ts, last_ts, seq, telemetry, fit, "
                       "raw, line, line_offset, match_offset, line_chars, line_cut, suspicious, others, events) "
                       "VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                           key, index, host, strength, ts_text, ts_text, self._seq, telemetry,
                           int(self._fits(index, telemetry)), json.dumps(raw, ensure_ascii=False, default=str),
                           excerpt, line_offset, match_offset, line_chars, int(len(excerpt) < line_chars),
                           int(bool(injection_flags(excerpt))), others,
                           json.dumps([str(event)[:128] for event in list(linked)[:MAX_LINKED_EVENTS]])))
            db.execute("INSERT INTO host VALUES (?, 1) ON CONFLICT (host) DO UPDATE SET kept = kept + 1", (host,))
            db.execute("INSERT INTO pat VALUES (?, 1) ON CONFLICT (pattern) DO UPDATE SET kept = kept + 1", (index,))
        except sqlite3.OperationalError as error:
            # a write the stage file could not take (its volume is full): this group is not kept
            self.stage_error = self.stage_error or f"writing the mention stage failed ({error})"
            self._lose(db, key, index, host, "stage")
            return
        self._groups += 1
        self._count_line(db, index, host, False)

    # ---- the pool -------------------------------------------------------------------------------------------------
    def ranked(self):
        """The kept groups in pool order, with their pattern's distinct hosts and matching lines (a pattern counted
        only past the pair bound still ranks, by its counted lines)."""
        if self.db is None:
            return
        self.db.execute("DROP TABLE IF EXISTS rarity")
        self.db.execute("CREATE TEMP TABLE rarity (pattern INTEGER PRIMARY KEY, hosts INTEGER NOT NULL, "
                        "lines INTEGER NOT NULL)")
        self.db.execute("INSERT INTO rarity SELECT pattern, count(*), sum(lines) FROM seen GROUP BY pattern")
        for (pattern, kind), count in self._overflow.items():
            if kind == "lines":
                self.db.execute("INSERT INTO rarity VALUES (?, 0, ?) ON CONFLICT (pattern) DO UPDATE SET "
                                "lines = lines + excluded.lines", (pattern, count))
        yield from self.db.execute(
            "SELECT g.key, g.pattern, g.host, g.n, g.first_ts, g.last_ts, g.telemetry, g.raw, g.line, g.line_chars, "
            "g.line_cut, g.suspicious, coalesce(r.hosts, 0), coalesce(r.lines, g.n), g.others, g.fit, g.line_offset, "
            "g.match_offset, g.raw_kept, g.events FROM grp g LEFT JOIN rarity r USING (pattern) "
            "ORDER BY g.strength DESC, g.fit DESC, coalesce(r.hosts, 0), coalesce(r.lines, g.n), "
            "g.first_ts IS NULL, g.first_ts, g.key")

    def losses(self):
        """Every (pattern, host) with lines not kept, the strongest patterns first."""
        if self.db is None:
            return
        patterns = self.patterns.patterns
        self.db.execute("DROP TABLE IF EXISTS strength")
        self.db.execute("CREATE TEMP TABLE strength (pattern INTEGER PRIMARY KEY, rank INTEGER NOT NULL)")
        self.db.executemany("INSERT INTO strength VALUES (?, ?)",
                            [(i, STRENGTH_RANK[p.strength]) for i, p in enumerate(patterns)])
        for pattern, host, lost in self.db.execute(
                "SELECT s.pattern, s.host, s.lost FROM seen s JOIN strength r USING (pattern) WHERE s.lost > 0 "
                "ORDER BY r.rank DESC, s.lost DESC, s.pattern, s.host"):
            yield {"pattern_id": patterns[pattern].id, "strength": patterns[pattern].strength, "host": host,
                   "lines_not_kept": lost}
        # (pattern, host) pairs counted past the remembered-pair bound: one row per pattern, their hosts not named
        for (pattern, kind), lost in sorted(self._overflow.items(),
                                            key=lambda item: (-STRENGTH_RANK[patterns[item[0][0]].strength],
                                                              item[0][0])):
            if kind == "lost" and lost:
                yield {"pattern_id": patterns[pattern].id, "strength": patterns[pattern].strength,
                       "host": PAST_PAIR_BOUND, "lines_not_kept": lost}

    def _cap_view(self, name: str, limit: int) -> dict | None:
        counted = self.caps[name]
        if not counted:
            return None
        return {"limit": limit, "groups_not_kept": sum(counted.values()),
                "patterns": [pattern for pattern, _n in counted.most_common(NAMES_SHOWN)]}

    def summary(self) -> dict:
        """The pool's coverage: what was scanned, what was not and why, and every cap that was hit."""
        stats = self.stats
        loaded = self.patterns.summary()
        lost_lines = (stats["lines_not_staged"] + stats["lines_not_published"]
                      + sum(count for (_pattern, kind), count in self._overflow.items() if kind == "lost"))
        lost_hosts = 0
        strong_lost_hosts = 0
        if self.db is not None:
            try:
                lost_lines += self.db.execute("SELECT coalesce(sum(lost), 0) FROM seen").fetchone()[0]
                lost_hosts = self.db.execute("SELECT count(DISTINCT host) FROM seen WHERE lost > 0").fetchone()[0]
                strong = [i for i, p in enumerate(self.patterns.patterns) if p.strength == "strong"]
                if strong:
                    marks = ",".join("?" * len(strong))
                    strong_lost_hosts = self.db.execute(
                        f"SELECT count(DISTINCT host) FROM seen WHERE lost > 0 AND pattern IN ({marks})",
                        strong).fetchone()[0]
            except (sqlite3.Error, OSError) as error:
                self._fail(f"the mention stage could not be read ({type(error).__name__}: {error})"[:300])
        caps = {name: view for name, limit in (("per_pattern", self.max_per_pattern), ("per_host", self.max_per_host),
                                               ("per_hunt", self.max_per_hunt), ("stage", 0), (DISK_RECLAIMED, 0))
                if (view := self._cap_view(name, limit)) is not None}
        reasons = []
        if not self.patterns.patterns:
            reasons.append("no mention patterns are loaded: unparsed text was not scanned")
        refused_all = self.patterns.refused
        for refused in refused_all[:REFUSALS_NAMED]:
            if refused.get("pattern") is None:
                reasons.append(f"pattern file {refused['name']} was refused, its patterns did not run: "
                               f"{refused['error']}")
            else:
                reasons.append(f"pattern {refused['pattern']} refused, it did not run: {refused['error']}")
        if len(refused_all) > REFUSALS_NAMED:
            reasons.append(f"{len(refused_all) - REFUSALS_NAMED} further pattern(s) or file(s) were refused and did not "
                           f"run (the first {REFUSED_SHOWN} are listed under patterns.refused, every one is counted in "
                           "patterns.refused_total)")
        if self.pin_changes:
            reasons.append("the pattern files differ from those pinned when the hunt was created: "
                           + ", ".join(self.pin_changes))
        if self.unscanned_count:
            reasons.append(f"{self.unscanned_count} partition(s) were not read in full, so their records were not "
                           "all offered to the scan (listed under unscanned_partitions)")
        if self.left_out:
            names = ", ".join(f"{item['target']} {item['kind']} {item['name']}" for item in self.left_out[:10])
            reasons.append(f"{len(self.left_out)} source(s) the sweep's fetch filters leave out were not scanned: "
                           f"{names}{' and others' if len(self.left_out) > 10 else ''}")
        for target, row in sorted(self.residue.items()):
            if not row["counted"]:
                reasons.append(f"{target}: {row['reason']}; its sources the sweep's fetch filters leave out were not "
                               "offered")
            elif row["records"] and row["read"] < row["records"]:
                named = ", ".join(f"{item['key']} ({item['not_read']:,} of {item['records']:,})"
                                  for item in row["keys"][:10])
                more = row["keys_not_read_in_full"] - min(10, len(row["keys"]))
                reasons.append(f"{target}: {row['records'] - row['read']:,} of {row['records']:,} record(s) outside "
                               f"the sweep's selection were not scanned ({row['reason']})"
                               + (f"; keys not read in full: {named}" if named else "")
                               + (f" and {more} more" if more > 0 else ""))
            if row["counted"] and row.get("drift"):
                reasons.append(f"{target}: {row['drift']}")
        for why, count in sorted(self.not_scanned.items()):
            reasons.append(f"{count} record(s) not scanned: {why}")
        for why, count in sorted(self.in_part.items()):
            reasons.append(f"{count} record(s) scanned only in part: {why}")
        if stats["lines_cut"]:
            reasons.append(f"{stats['lines_cut']} record(s) whose text is longer than the scan bound "
                           f"({MAX_SCAN_CHARS} characters) were scanned only in part "
                           f"({stats['chars_not_scanned']} characters not scanned)")
        if lost_lines:
            why = sorted(name for name, view in caps.items())
            if stats["lines_not_staged"] or stats["lines_not_published"]:
                why.append("the stage failed")
            if self.lower_bound or self._overflow:
                why.append("groups past the remembered-key or pair bound")
            if stats["groups_evicted"] and not why:
                why.append("evicted by stronger patterns or rarer hosts")
            reasons.append(f"{lost_lines} matching line(s) were not kept in the pool ({', '.join(why) or 'a cap'})")
        if self.stage_error:
            reasons.append(f"the mention stage refused writes: {self.stage_error}")
        if self.stage_refusal:
            reasons.append(f"the hunt's state budget asked the mention pool to give way: {self.stage_refusal}")
        if stats["records_reclaimed"]:
            reasons.append(f"{stats['records_reclaimed']} kept record(s) were released to give disk to detection "
                           "(their mentions keep the source reference and the excerpt)")
        if stats["lines_" + TRIES_EXHAUSTED]:
            reasons.append(f"{stats['lines_' + TRIES_EXHAUSTED]} line(s) held an anchored pattern's literal prefix "
                           f"more often than it is tried ({MAX_PREFIX_TRIES}) without a match: not ruled out")
        if stats["lines_" + WINDOW_CUT]:
            reasons.append(f"{stats['lines_' + WINDOW_CUT]} line(s) went on past an anchored pattern's window "
                           f"({REGEX_WINDOW} characters) without a match: not ruled out")
        if self.lower_bound or self._overflow:
            reasons.append("some groups not kept were not remembered: the count of groups not kept is a lower "
                           "bound (every line is counted exactly)")
        if stats["scan_failures"]:
            reasons.append(f"the scan failed on {stats['scan_failures']} partition(s); their records were not all "
                           "scanned (listed under unscanned_partitions)")
        if self.publish_error:
            reasons.append(f"the pool was not stored: {self.publish_error}")
        if self.stopped:
            reasons.append(f"the sweep stopped before it read every partition: {self.stopped}")
        status = ("not_scanned" if not self.patterns.patterns else "partial" if reasons else SCANNED_ALL)
        return {
            "label": MENTION_LABEL, "lane": MENTION_LANE, "status": status,
            "status_text": {SCANNED_ALL: SCANNED_ALL_TEXT, "partial": "partial", "not_scanned": "not scanned"}[status],
            "reasons": reasons, "patterns": loaded, "pattern_changes": list(self.pin_changes),
            "records_offered": stats["records_offered"], "lines_scanned": stats["lines_scanned"],
            "lines_matched": stats["lines_matched"], "by_telemetry": dict(self.by_telemetry),
            "records_scanned": stats["records_scanned"], "by_field": dict(self.by_field.most_common(MAX_FIELD_KEYS)),
            "records_without_free_text": dict(self.no_free_text),
            "not_scanned": {"records": dict(self.not_scanned), "records_in_part": dict(self.in_part),
                            "lines_cut_at_bound": stats["lines_cut"],
                            "chars_past_bound": stats["chars_not_scanned"],
                            "cut_line_hosts": [{"host": host, "lines": n}
                                               for host, n in self.cut_hosts.most_common(NAMES_SHOWN)],
                            "cut_lines_on_other_hosts": stats["cut_lines_on_other_hosts"],
                            "cut_line_records": list(self.cut_records)},
            "unscanned_partitions": {"count": self.unscanned_count, "listed": list(self.unscanned)},
            "left_out_sources": list(self.left_out),
            "outside_selection": {
                "records": sum(row["records"] or 0 for row in self.residue.values()),
                "read": sum(row["read"] for row in self.residue.values()),
                "offered": stats["residue_offered"],
                "targets_not_counted": sorted(target for target, row in self.residue.items() if not row["counted"]),
                "targets": {target: dict(row) for target, row in sorted(self.residue.items())}},
            "groups_kept": self._groups, "groups_evicted": stats["groups_evicted"],
            "lines_not_kept": lost_lines, "caps": caps,
            "hosts_with_lines_not_kept": lost_hosts, "hosts_with_strong_lines_not_kept": strong_lost_hosts,
            "groups_not_kept_lower_bound": bool(self.lower_bound or self._overflow),
            "records_reclaimed_for_detection": stats["records_reclaimed"],
            "not_ruled_out": {"prefix_tries_exhausted": stats["lines_" + TRIES_EXHAUSTED],
                              "window_cut": stats["lines_" + WINDOW_CUT]},
        }

    def publish(self, repo, *, owner_token: str | None = None) -> dict:
        """Rank the pool and replace the hunt's stored pool with it, in one transaction; returns the summary."""
        summary = self.summary()
        patterns = self.patterns.patterns
        now = datetime.now(UTC)

        def rows():
            for rank, (key, index, host, count, first_ts, last_ts, telemetry, raw, line, line_chars, line_cut,
                       suspicious, hosts, lines, others, fit, line_offset, match_offset, raw_kept,
                       events) in enumerate(
                           self.ranked() or (), start=1):
                pattern = patterns[index]
                record = json.loads(raw)
                record["ts"] = _parse(record.get("ts"))
                yield ({
                    "id": "mn-" + hashlib.sha256(json.dumps([self.hunt_id, key]).encode()).hexdigest()[:24],
                    "hunt_id": self.hunt_id, "rank": rank, "pattern_id": pattern.id,
                    "pattern_title": pattern.title, "strength": pattern.strength,
                    "pattern_attack": list(pattern.attack),
                    "also_matched": [{"id": patterns[other].id, "title": patterns[other].title,
                                      "strength": patterns[other].strength} for other in json.loads(others)],
                    "pattern_source": pattern.source.model_dump(), "telemetry": telemetry,
                    "telemetry_fit": bool(fit), "host": host,
                    "target": record["target"], "native_id": record["native_id"],
                    "raw_id": raw_record_id(self.hunt_id, record["target"], record["native_id"]),
                    "first_ts": _parse(first_ts), "last_ts": _parse(last_ts), "count": count,
                    "pattern_hosts": hosts, "pattern_lines": lines, "line": line, "line_chars": line_chars,
                    "line_offset": line_offset, "match_offset": match_offset,
                    "line_cut": bool(line_cut), "suspicious_content": bool(suspicious), "created_at": now,
                    "linked_events": json.loads(events),
                }, {**record, "origin": MENTION_ORIGIN})

        def losses():
            for item in self.losses() or ():
                yield {"hunt_id": self.hunt_id, **item}
        try:
            repo.replace_mentions(self.hunt_id, rows(), summary, owner_token=owner_token, losses=losses())
        except (sqlite3.Error, OSError) as error:
            # the stage could not be read back (the store's own errors are not caught here): the store's
            # transaction rolled back, so the hunt keeps an empty pool whose coverage says why
            self._fail(f"the mention stage could not be read ({type(error).__name__}: {error})"[:300])
            self.publish_error = self.stage_error
            self.stats["lines_not_published"] += summary["lines_matched"] - summary["lines_not_kept"]
            self._groups = 0
            summary = self.summary()
            repo.replace_mentions(self.hunt_id, iter(()), summary, owner_token=owner_token)
        return summary
