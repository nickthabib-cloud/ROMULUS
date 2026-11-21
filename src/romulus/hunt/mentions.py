"""The mention sweep: curated patterns over the raw text of records no normalizer read.

The sweep hands each partition's unread records (`normalize_hits(unread=...)`: records of a dataset or event class no
normalizer reads, text in no recognized format or too long to parse, and records a normalizer failed on; never a
duplicate copy of a normalized record) to `MentionScanner.scan`. The scanner reads one typed text field per record
(`message`, else `event.original`), never a serialized record, bounds it (`evidence.mentions.MAX_SCAN_CHARS`), and runs
the hunt's patterns for the record's telemetry class over it.

Every match is grouped by (pattern, host, normalized line) in a private SQLite stage under the hunt's stage directory,
charged to the hunt's state budget, so memory stays bounded however many lines match. A group keeps its count, first
and last time, and its first record as the citation: the record cleaned, redacted and bounded the way the raw-record
path keeps a record (`evidence.raw_citation`), and the matched line, redacted and bounded.

The pool is bounded per pattern, per host and per hunt. A group past a cap is not kept; its lines are still counted
under its pattern and host, so every remainder is exact. At the host and hunt caps a stronger pattern's new group
takes the place of a weaker one (the weaker one's lines move to the counted remainder), so a flood of weak matches
never crowds out a strong one. Any cap that is hit, any refused pattern file, any line cut at the scan bound and any
write the stage could not take make the pool's coverage partial, with the counts and names of what was not kept or
not scanned. With no patterns loaded the pool is `not_scanned`, never empty.

At the end of the sweep the pool is ranked (pattern strength, then rarity: the pattern's distinct hosts and then its
matching lines, fewest first; then first time) and published in one transaction that replaces the hunt's earlier
pool, so a sweep run again on resume leaves one pool.
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
from romulus.content.mention_patterns import PatternSet
from romulus.evidence.linux_catalog import text_payload
from romulus.evidence.mention_match import (
    MAX_PREFIX_TRIES,
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
from romulus.evidence.windows import is_windows_source
from romulus.sources.compile import time_unit
from romulus.store.db import digest

STAGE_PREFIX = "romulus-stage-"         # the event stage's prefix: a killed process's leftover is cleared the same way
MENTION_ORIGIN = "mention_sweep"
# the pool's bounds (groups of identical (pattern, host, normalized line)); every match past them is still counted
MAX_GROUPS_PER_PATTERN = 2_000
MAX_GROUPS_PER_HOST = 2_000
MAX_GROUPS_PER_HUNT = 20_000
# the matched line kept on a mention (the whole record is kept, bounded, on its raw record)
MAX_LINE_CHARS = 1_024
# The keys of groups past a cap that the stage remembers (so their later lines are counted under the same group), and
# the (pattern, host) pairs it counts lines for. Past either bound, and while the hunt's state budget asks the pool to
# give way, every line is still counted exactly; only the number of distinct groups not kept becomes a lower bound,
# and a pattern's distinct hosts (its rarity) a lower bound too.
MAX_GONE_KEYS = 200_000
MAX_SEEN_PAIRS = 1_000_000
MAX_HOST_CHARS = 255
# names listed per cap in the coverage summary (the counts cover all)
NAMES_SHOWN = 20
NO_HOST = ""
_HOST_FIELDS = ("host.name", "host.hostname", "agent.hostname", "computer_name", "winlog.computer_name")


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
                 window: tuple[datetime, datetime] | None = None,
                 max_per_pattern: int = MAX_GROUPS_PER_PATTERN, max_per_host: int = MAX_GROUPS_PER_HOST,
                 max_per_hunt: int = MAX_GROUPS_PER_HUNT):
        self.hunt_id = hunt_id
        self.patterns = patterns
        self.settings = settings
        self.window = window
        self.stage_dir = stage_dir
        self.budget = budget
        # a store no detection reads: it gives way before any detection store refuses a key, and has no floor
        self.account = budget.account("mention_pool", yields=True) if budget is not None else None
        self.max_per_pattern, self.max_per_host, self.max_per_hunt = max_per_pattern, max_per_host, max_per_hunt
        self._matchers: dict[str, MentionMatcher | None] = {}
        self._dir: str | None = None
        self.db: sqlite3.Connection | None = None
        self._size = 0
        self._groups = 0
        self._seq = 0
        self.stats = Counter()
        self.by_telemetry: Counter = Counter()
        self.caps: dict[str, Counter] = {"per_pattern": Counter(), "per_host": Counter(), "per_hunt": Counter(),
                                         "stage": Counter()}
        self.stage_error = ""
        self._gone = 0
        self._seen = 0
        self._overflow: Counter = Counter()      # (pattern index, "lines" | "lost") past the pair bound
        self.lower_bound = False                 # some distinct groups not kept were not remembered
        self._broken = False            # the stage failed: later matches are counted, never kept
        self.publish_error = ""
        self.stage_refusal = ""
        self.stopped = ""

    # ---- matching -------------------------------------------------------------------------------------------------
    def _matcher(self, telemetry: str) -> MentionMatcher | None:
        if telemetry not in self._matchers:
            chosen = [built for built, pattern in zip(self.patterns.compiled, self.patterns.patterns, strict=True)
                      if "any" in pattern.telemetry or telemetry in pattern.telemetry]
            self._matchers[telemetry] = MentionMatcher(chosen) if chosen else None
        return self._matchers[telemetry]

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

    def scan(self, target: str, contract, unread: list[tuple], task_id: str | None) -> None:
        """Scan one partition's unread records: (hit, why no normalizer read it[, whether it is a Windows event
        record]) as `normalize_hits(unread=...)` lists them."""
        if not unread:
            return
        stats = self.stats
        stats["records_offered"] += len(unread)
        for entry in unread:
            hit = entry[0]
            source = hit.get("_source")
            payload = text_payload(source) if isinstance(source, dict) else None
            if payload is None:
                stats["no_text"] += 1
                continue
            telemetry = telemetry_class(source, contract, entry[2] if len(entry) > 2 else None)
            matcher = self._matcher(telemetry)
            if matcher is None:
                stats["no_patterns_for_telemetry"] += 1
                continue
            text, past = bound_text(payload[1])
            stats["lines_scanned"] += 1
            self.by_telemetry[telemetry] += 1
            if past:
                stats["lines_cut"] += 1
                stats["chars_not_scanned"] += past
            unresolved: set[str] = set()
            matched = matcher.match(text, cut=bool(past), unresolved=unresolved)
            for note in unresolved:
                stats["lines_" + note] += 1
            if not matched:
                continue
            stats["lines_matched"] += 1
            if self._broken:
                stats["lines_not_staged"] += 1
                continue
            try:
                self._keep(target, contract, hit, payload[0], text, matched, task_id, telemetry)
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
            db.execute("PRAGMA journal_mode=MEMORY")
            db.execute("PRAGMA synchronous=OFF")
            db.execute("CREATE TABLE grp (key TEXT PRIMARY KEY, pattern INTEGER NOT NULL, host TEXT NOT NULL, "
                       "strength INTEGER NOT NULL, n INTEGER NOT NULL, first_ts TEXT, last_ts TEXT, "
                       "seq INTEGER NOT NULL, telemetry TEXT NOT NULL, raw TEXT NOT NULL, line TEXT NOT NULL, "
                       "line_chars INTEGER NOT NULL, line_cut INTEGER NOT NULL, suspicious INTEGER NOT NULL)")
            db.execute("CREATE INDEX grp_weak ON grp (strength, pattern, seq)")
            db.execute("CREATE INDEX grp_host ON grp (host, strength, seq)")
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
        every store's physical writes are capped against."""
        if self.db is None or self.budget is None or self.account is None:
            return
        size = self.db.execute("PRAGMA page_count").fetchone()[0] * self._page
        delta = size - self._size
        if delta:
            self.budget.charge(self.account, delta)
            self.budget.physical_account(self.account, delta)
            if delta > 0:
                self.budget.grew(delta)
            else:
                self.budget._physical_released += -delta
            self._size = size

    def _refusal(self) -> str:
        """Why the stage may take no new row now ("" while it may)."""
        if self.budget is None or self.account is None:
            return ""
        return self.budget.new_key_reason(self.account)

    def touch(self) -> None:
        """Mark the stage live, so another hunt's stale-stage cleanup never removes it."""
        if self._dir is not None:
            with contextlib.suppress(OSError):
                os.utime(self._dir)

    def close(self) -> None:
        if self.db is not None:
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

    def _lose(self, db, key: str, pattern: int, host: str, cap: str) -> None:
        """A new group past a cap: not kept, its key remembered (while the bound allows) so its later lines count
        as not kept too."""
        if self._gone < MAX_GONE_KEYS and not self._refusal():
            if db.execute("INSERT OR IGNORE INTO gone VALUES (?, ?, ?)", (key, pattern, host)).rowcount:
                self._gone += 1
            self.caps[cap][self.patterns.patterns[pattern].id] += 1
        else:
            self.lower_bound = True
        self._count_line(db, pattern, host, True)

    def _evict(self, db, where: str, params: tuple, strength: int) -> bool:
        """Drop the weakest kept group under `where` when it is weaker than `strength`: its lines become not kept."""
        victim = db.execute(f"SELECT key, pattern, host, n, strength FROM grp WHERE {where} AND strength < ? "
                            "ORDER BY strength, seq DESC LIMIT 1", (*params, strength)).fetchone()
        if victim is None:
            return False
        key, pattern, host, lines, _strength = victim
        db.execute("DELETE FROM grp WHERE key = ?", (key,))
        if self._gone < MAX_GONE_KEYS:
            if db.execute("INSERT OR IGNORE INTO gone VALUES (?, ?, ?)", (key, pattern, host)).rowcount:
                self._gone += 1
        else:
            self.lower_bound = True
        db.execute("UPDATE seen SET lost = lost + ? WHERE pattern = ? AND host = ?", (lines, pattern, host))
        db.execute("UPDATE host SET kept = kept - 1 WHERE host = ?", (host,))
        db.execute("UPDATE pat SET kept = kept - 1 WHERE pattern = ?", (pattern,))
        self._groups -= 1
        self.stats["groups_evicted"] += 1
        return True

    def _keep(self, target: str, contract, hit: dict, path: str, text: str, matched: list[int],
              task_id: str | None, telemetry: str) -> None:
        db = self._open()
        host = record_host(hit["_source"])
        normalized = line_digest(text)
        when: tuple | None = None
        for index in matched:
            pattern = self.patterns.patterns[index]
            key = hashlib.sha256(json.dumps([pattern.id, host, normalized]).encode()).hexdigest()[:32]
            if when is None:
                ts, _text = record_time(hit["_source"], getattr(contract, "time_field", None),
                                        unit=time_unit(contract) if contract is not None else "ms",
                                        window=self.window)
                when = (_iso(ts),)
            ts_text = when[0]
            if db.execute("UPDATE grp SET n = n + 1, first_ts = CASE WHEN first_ts IS NULL OR "
                          "(? IS NOT NULL AND ? < first_ts) THEN coalesce(?, first_ts) ELSE first_ts END, "
                          "last_ts = CASE WHEN last_ts IS NULL OR (? IS NOT NULL AND ? > last_ts) "
                          "THEN coalesce(?, last_ts) ELSE last_ts END WHERE key = ?",
                          (ts_text, ts_text, ts_text, ts_text, ts_text, ts_text, key)).rowcount:
                self._count_line(db, index, host, False)
                continue
            if db.execute("SELECT 1 FROM gone WHERE key = ?", (key,)).fetchone() is not None:
                self._count_line(db, index, host, True)
                continue
            strength = STRENGTH_RANK[pattern.strength]
            kept_pattern = (db.execute("SELECT kept FROM pat WHERE pattern = ?", (index,)).fetchone() or (0,))[0]
            if kept_pattern >= self.max_per_pattern:
                self._lose(db, key, index, host, "per_pattern")
                continue
            kept_host = (db.execute("SELECT kept FROM host WHERE host = ?", (host,)).fetchone() or (0,))[0]
            if kept_host >= self.max_per_host and not self._evict(db, "host = ?", (host,), strength):
                self._lose(db, key, index, host, "per_host")
                continue
            if self._groups >= self.max_per_hunt and not self._evict(db, "1 = 1", (), strength):
                self._lose(db, key, index, host, "per_hunt")
                continue
            if refusal := self._refusal():
                # the hunt's state budget asks the pool to give way: new groups are counted, not kept
                self.stage_refusal = self.stage_refusal or refusal
                self._lose(db, key, index, host, "stage")
                continue
            raw = build_raw_record(
                self.hunt_id, hit, source_kind="index", time_field=getattr(contract, "time_field", None),
                session_id=None, task_id=task_id,
                query_digest="mention:" + digest({"pattern": pattern.id, "task": task_id})[:24],
                query_text=(f"mention sweep: pattern {pattern.id} matched the record's {path} in the deterministic "
                            f"sweep of {target}"),
                redact=self._redact, flagged=injection_flags,
                time_unit=time_unit(contract) if contract is not None else "ms", window=self.window)
            raw["ts"] = _iso(raw["ts"])
            line = self._redact_text(text)
            shown = line[:MAX_LINE_CHARS]
            self._seq += 1
            try:
                db.execute("INSERT INTO grp VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                    key, index, host, strength, ts_text, ts_text, self._seq, telemetry,
                    json.dumps(raw, ensure_ascii=False, default=str), shown, len(line), int(len(line) > len(shown)),
                    int(bool(injection_flags(line)))))
                db.execute("INSERT INTO host VALUES (?, 1) ON CONFLICT (host) DO UPDATE SET kept = kept + 1",
                           (host,))
                db.execute("INSERT INTO pat VALUES (?, 1) ON CONFLICT (pattern) DO UPDATE SET kept = kept + 1",
                           (index,))
            except sqlite3.OperationalError as error:
                # a write the stage file could not take (its volume is full): this group is not kept
                self.stage_error = self.stage_error or f"writing the mention stage failed ({error})"
                self._lose(db, key, index, host, "stage")
                continue
            self._groups += 1
            self._count_line(db, index, host, False)

    # ---- the pool -------------------------------------------------------------------------------------------------
    def ranked(self):
        """The kept groups in pool order, with their pattern's distinct hosts and matching lines."""
        if self.db is None:
            return
        self.db.execute("DROP TABLE IF EXISTS rarity")
        self.db.execute("CREATE TEMP TABLE rarity AS SELECT pattern, count(*) AS hosts, sum(lines) AS lines "
                        "FROM seen GROUP BY pattern")
        for (pattern, kind), count in self._overflow.items():
            if kind == "lines":
                self.db.execute("UPDATE rarity SET lines = lines + ? WHERE pattern = ?", (count, pattern))
        yield from self.db.execute(
            "SELECT g.key, g.pattern, g.host, g.n, g.first_ts, g.last_ts, g.telemetry, g.raw, g.line, g.line_chars, "
            "g.line_cut, g.suspicious, r.hosts, r.lines FROM grp g JOIN rarity r USING (pattern) "
            "ORDER BY g.strength DESC, r.hosts, r.lines, g.first_ts IS NULL, g.first_ts, g.key")

    def _cap_view(self, name: str, limit: int) -> dict | None:
        counted = self.caps[name]
        if not counted:
            return None
        view = {"limit": limit, "groups_not_kept": sum(counted.values()),
                "patterns": [pattern for pattern, _n in counted.most_common(NAMES_SHOWN)]}
        return view

    def summary(self) -> dict:
        """The pool's coverage: what was scanned, what was not and why, and every cap that was hit."""
        stats = self.stats
        loaded = self.patterns.summary()
        lost_lines = (stats["lines_not_staged"] + stats["lines_not_published"]
                      + sum(count for (_pattern, kind), count in self._overflow.items() if kind == "lost"))
        lost_hosts: list[tuple[str, int]] = []
        if self.db is not None:
            try:
                lost_lines += self.db.execute("SELECT coalesce(sum(lost), 0) FROM seen").fetchone()[0]
                lost_hosts = self.db.execute(
                    "SELECT host, sum(lost) FROM seen GROUP BY host HAVING sum(lost) > 0 ORDER BY sum(lost) DESC, "
                    f"host LIMIT {NAMES_SHOWN}").fetchall()
            except (sqlite3.Error, OSError) as error:
                self._fail(f"the mention stage could not be read ({type(error).__name__}: {error})"[:300])
        caps = {name: view for name, limit in (("per_pattern", self.max_per_pattern), ("per_host", self.max_per_host),
                                               ("per_hunt", self.max_per_hunt), ("stage", 0))
                if (view := self._cap_view(name, limit)) is not None}
        if caps.get("per_host") is not None or caps.get("per_hunt") is not None or lost_hosts:
            caps.setdefault("hosts_with_lines_not_kept", [host or "(no host)" for host, _n in lost_hosts])
        reasons = []
        if not self.patterns.patterns:
            reasons.append("no mention patterns are loaded: unparsed text was not scanned")
        for refused in self.patterns.refused:
            reasons.append(f"pattern file {refused['name']} was refused, its patterns did not run: "
                           f"{refused['error']}")
        if stats["lines_cut"]:
            reasons.append(f"{stats['lines_cut']} line(s) longer than the scan bound were scanned only in part "
                           f"({stats['chars_not_scanned']} characters not scanned)")
        if stats["no_patterns_for_telemetry"] and self.patterns.patterns:
            reasons.append(f"{stats['no_patterns_for_telemetry']} record(s) of a telemetry class no loaded pattern "
                           "reads were not scanned")
        if lost_lines:
            why = sorted(name for name in caps if not name.startswith("hosts"))
            if stats["lines_not_staged"] or stats["lines_not_published"]:
                why.append("the stage failed")
            reasons.append(f"{lost_lines} matching line(s) were not kept in the pool ({', '.join(why)})")
        if self.stage_error:
            reasons.append(f"the mention stage refused writes: {self.stage_error}")
        if self.stage_refusal:
            reasons.append(f"the hunt's state budget asked the mention pool to give way: {self.stage_refusal}")
        if stats["lines_" + TRIES_EXHAUSTED]:
            reasons.append(f"{stats['lines_' + TRIES_EXHAUSTED]} line(s) held an anchored pattern's literal prefix "
                           f"more often than it is tried ({MAX_PREFIX_TRIES}) without a match: not ruled out")
        if stats["lines_" + WINDOW_CUT]:
            reasons.append(f"{stats['lines_' + WINDOW_CUT]} line(s) went on past an anchored pattern's window "
                           f"({REGEX_WINDOW} characters) without a match: not ruled out")
        if self.lower_bound or self._overflow:
            reasons.append("some groups not kept were not remembered: the count of groups not kept is a lower "
                           "bound (every line is counted exactly)")
        if self.publish_error:
            reasons.append(f"the pool was not stored: {self.publish_error}")
        if self.stopped:
            reasons.append(f"the sweep stopped before it read every partition: {self.stopped}")
        status = "not_scanned" if not self.patterns.patterns else "partial" if reasons else "complete"
        return {
            "label": MENTION_LABEL, "lane": MENTION_LANE, "status": status, "reasons": reasons,
            "patterns": loaded,
            "records_offered": stats["records_offered"], "lines_scanned": stats["lines_scanned"],
            "lines_matched": stats["lines_matched"], "by_telemetry": dict(self.by_telemetry),
            "not_scanned": {"no_text_field": stats["no_text"],
                            "no_pattern_for_telemetry": stats["no_patterns_for_telemetry"],
                            "lines_cut_at_bound": stats["lines_cut"], "chars_past_bound": stats["chars_not_scanned"],
                            "records_not_fetched": ("records of datasets and event classes the sweep does not read "
                                                    "are not scanned; the coverage section's not-assessed list names "
                                                    "them")},
            "groups_kept": self._groups, "groups_evicted": stats["groups_evicted"],
            "lines_not_kept": lost_lines, "caps": caps,
            "groups_not_kept_lower_bound": bool(self.lower_bound or self._overflow),
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
                       suspicious, hosts, lines) in enumerate(self.ranked() or (), start=1):
                pattern = patterns[index]
                record = json.loads(raw)
                record["ts"] = _parse(record.get("ts"))
                yield ({
                    "id": "mn-" + hashlib.sha256(json.dumps([self.hunt_id, key]).encode()).hexdigest()[:24],
                    "hunt_id": self.hunt_id, "rank": rank, "pattern_id": pattern.id,
                    "pattern_title": pattern.title, "strength": pattern.strength,
                    "pattern_attack": list(pattern.attack),
                    "pattern_source": pattern.source.model_dump(), "telemetry": telemetry, "host": host,
                    "target": record["target"], "native_id": record["native_id"],
                    "raw_id": raw_record_id(self.hunt_id, record["target"], record["native_id"]),
                    "first_ts": _parse(first_ts), "last_ts": _parse(last_ts), "count": count,
                    "pattern_hosts": hosts, "pattern_lines": lines, "line": line, "line_chars": line_chars,
                    "line_cut": bool(line_cut), "suspicious_content": bool(suspicious), "created_at": now,
                }, {**record, "origin": MENTION_ORIGIN})
        try:
            repo.replace_mentions(self.hunt_id, rows(), summary, owner_token=owner_token)
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
