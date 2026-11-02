"""Compact authentication keys and native references; source bodies are re-read only for publication.

Active burst rows expire into a disk archive, never out of detection history: targets and late
records may arrive in any order. Replay reads both tables. Only the stated disk budget can
refuse history; neither a timestamp watermark nor a memory bound discards a witness.
Repeated principals, clients, service names and reporting hosts are interned on disk. Stable
hexadecimal event ids use their binary representation. Only predicate values and their reconstructable
provenance are dictionary encoded; no full event or raw JSON is copied here.
"""
from __future__ import annotations

import json
import sqlite3
from array import array
from datetime import UTC, datetime

from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_rows import WindowsRows
from romulus.evidence.typed import RawRef, TypedEvent, fv


def _stored_id(identity):
    if len(identity) in {24, 64}:
        try:
            packed = bytes.fromhex(identity)
            if packed.hex() == identity:
                return packed
        except ValueError:
            pass
    return identity


def _event_id(value):
    return value.hex() if isinstance(value, bytes) else value


class BurstRows(WindowsRows):
    def __init__(self, owner):
        super().__init__(owner)
        self.watermark = float("-inf")
        self._last_refused = None

    def store(self):
        spill = self.owner.spill()
        if not self.ready:
            spill.db.execute("PRAGMA journal_mode=MEMORY")
            spill.db.execute("CREATE TABLE windows_symbols(id INTEGER PRIMARY KEY,value TEXT UNIQUE)")
            spill.db.execute("CREATE TABLE windows_refs(id BLOB PRIMARY KEY,target INTEGER,native TEXT,"
                             "fields BLOB,template INTEGER) WITHOUT ROWID")
            for table in ("windows_rows", "windows_archive"):
                spill.db.execute(f"CREATE TABLE {table}(k INTEGER,id BLOB,ts REAL,value INTEGER,host INTEGER,"
                                 "PRIMARY KEY(k,id)) WITHOUT ROWID")
                spill.db.execute(f"CREATE INDEX {table}_time ON {table}(k,ts,id)")
                spill.db.execute(f"CREATE INDEX {table}_value ON {table}(k,value,host,ts)")
            spill.db.execute("CREATE INDEX windows_rows_expiry ON windows_rows(ts)")
            spill.db.execute("CREATE VIEW windows_all AS SELECT k.value k,w.id,w.ts,v.value value,h.value host FROM "
                             "(SELECT * FROM windows_rows UNION ALL SELECT * FROM windows_archive) w "
                             "JOIN windows_symbols k ON k.id=w.k JOIN windows_symbols v ON v.id=w.value "
                             "JOIN windows_symbols h ON h.id=w.host")
            spill.db.execute("CREATE TABLE windows_marks(k TEXT PRIMARY KEY,value TEXT) WITHOUT ROWID")
            self.account = self.owner.state_budget().account(f"{self.owner.id}:windows_rows", strong=True)
            self.ready = True
            self._charge()
        return spill

    def _charge(self):
        # Charge allocated pages, including indexes and symbols, rather than a favorable payload estimate.
        db = self.owner.spill().db
        size = db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0]
        self.owner.state_budget().charge(self.account, size-self.account.used)

    def _write(self, statement, rows):
        spill = self.store()
        budget = self.owner.state_budget()
        budget.check_free()
        reason = budget.new_key_reason(self.account)
        if reason:
            raise StateExhausted(reason)
        available = min(max(0, budget.disk_total-budget.physical_used),
                        max(0, budget.floor_of(self.account)-self.account.used) +
                        max(0, budget.pool-budget.physical_pool_used))
        headroom = budget.headroom()
        if headroom is not None:
            available = min(available, headroom)
        pages = spill.db.execute("PRAGMA page_count").fetchone()[0]
        spill.db.execute(f"PRAGMA max_page_count={pages+available//spill._page}")
        try:
            spill.db.executemany(statement, rows)
        except sqlite3.OperationalError as exc:
            spill.db.rollback()
            if "full" in str(exc).lower():
                raise StateExhausted("authentication state reached its hunt byte allowance or volume reserve") from exc
            raise
        finally:
            spill.grew()
            self._charge()

    def _symbol(self, value):
        existing = self._lookup(value)
        if existing is not None:
            return existing
        self._write("INSERT INTO windows_symbols(value) VALUES(?)", [(value,)])
        return self.store().db.execute("SELECT last_insert_rowid()").fetchone()[0]

    def _lookup(self, value):
        row = self.store().execute("SELECT id FROM windows_symbols WHERE value=?", (value,)).fetchone()
        return row[0] if row else None

    def put(self, key, event, value=""):
        spill = self.store()
        key_id = self._lookup(key)
        if key_id is not None and spill.execute(
                "SELECT 1 FROM windows_rows WHERE k=? AND id=? UNION ALL "
                "SELECT 1 FROM windows_archive WHERE k=? AND id=? LIMIT 1",
                (key_id, _stored_id(event.id), key_id, _stored_id(event.id))).fetchone():
            return False
        if not self.room():
            self._refuse(event, "The disk budget refused an authentication correlation key")
            return False
        stamp = event.ts.timestamp()
        cutoff = max(self.watermark, stamp) - self.owner.seconds
        table = "windows_archive" if stamp < cutoff else "windows_rows"
        try:
            if not spill.execute("SELECT 1 FROM windows_refs WHERE id=?", (_stored_id(event.id),)).fetchone():
                # Origins and repeated values are dictionary encoded; record ids are never symbols.
                names = sorted(name for name in event.fields if name in self.owner.citation_fields)
                ref = event.raw[0]
                def origin(name):
                    value = event.fields[name].origin
                    return "{native}" + value[len(ref.native_id):] if value.startswith(ref.native_id+":") else value
                template = json.dumps([(name, origin(name)) for name in names] +
                                      [("@normalizer", event.normalizer), ("@outcome", event.outcome.value)])
                values = array("I", [self._symbol(json.dumps(event.get(name))) for name in names]).tobytes()
                self._write("INSERT INTO windows_refs VALUES(?,?,?,?,?)", [
                    (_stored_id(event.id), self._symbol(ref.target), ref.native_id, values, self._symbol(template))])
            # Non-distinct rules count records by their row identity, without interning each id a second time.
            if not self.owner.distinct:
                value = ""
            row = (self._symbol(key), _stored_id(event.id), stamp, self._symbol(value), self._symbol(event.host))
            self._write(f"INSERT INTO {table} VALUES(?,?,?,?,?)", [row])
            if stamp > self.watermark:
                # Rows move, rather than being forgotten; the archive also catches late cross-target windows.
                # Commit bounded moves so the in-memory rollback journal cannot grow with a whole
                # high-volume time window. A crash can leave both copies; readers deduplicate ids.
                while expired := spill.execute("SELECT * FROM windows_rows WHERE ts<? LIMIT 256", (cutoff,)).fetchall():
                    self._write("INSERT OR IGNORE INTO windows_archive VALUES(?,?,?,?,?)", expired)
                    self._write("DELETE FROM windows_rows WHERE k=? AND id=?", [(row[0], row[1]) for row in expired])
                self.watermark = stamp
        except StateExhausted as exc:
            self._refuse(event, f"An authentication correlation key could not be written: {exc}")
            self._charge()
            return False
        self._charge()
        return True

    def compact(self, identities):
        """Rebuild only cited, recorded fields. The source body is fetched at publication, if available."""
        out = []
        for identity in identities:
            row = self.store().execute(
                "SELECT r.target,r.native,r.fields,r.template,w.ts,w.host FROM windows_refs r JOIN "
                "(SELECT id,ts,host FROM windows_rows UNION ALL SELECT id,ts,host FROM windows_archive) w "
                "ON w.id=r.id WHERE r.id=? LIMIT 1", (_stored_id(identity),)).fetchone()
            if row is None:
                continue
            target, native, blob, template, stamp, host = row
            def symbol(number):
                return self.store().execute("SELECT value FROM windows_symbols WHERE id=?", (number,)).fetchone()[0]
            metadata = json.loads(symbol(template))
            fields = {name: fv(json.loads(symbol(number)), origin.replace("{native}", native, 1))
                      for (name, origin), number in zip(metadata[:-2], array("I", blob), strict=True)}
            out.append(TypedEvent(id=identity, family="auth", ts=datetime.fromtimestamp(stamp, UTC),
                                 host=symbol(host), outcome=metadata[-1][1], fields=fields,
                                 raw=[RawRef(target=symbol(target), native_id=native)], normalizer=metadata[-2][1],
                                 caveats=["Authentication witness body not retrieved; compact recorded fields and native reference retained."]))
        return out

    def _refuse(self, event, reason):
        # Source, reporter and daily indexes can each refuse the same input; count that record once.
        if self._last_refused != event.id:
            self._last_refused = event.id
            self.owner.refuse("windows_row_refused", reason)
        else:
            self.owner.note_limit("windows_row_refused", reason)

    def remember(self, key, value):
        if self.marker(key) is None and not self.room():
            return
        try:
            self._write("INSERT OR REPLACE INTO windows_marks VALUES(?,?)", [(key, value)])
            self._charge()
        except StateExhausted as exc:
            self.owner.note_limit("windows_marks", f"Correlation revision state could not be retained: {exc}")

    def first(self, key):
        if self.marked(key):
            return False
        if self.room():
            try:
                self._write("INSERT INTO windows_marks VALUES(?,?)", [(key, "")])
                self._charge()
            except StateExhausted as exc:
                self.owner.note_limit("windows_marks", f"Correlation dedup markers could not be retained: {exc}")
        return True

    def prior_value(self, key, stamp, value, host, identity, bucket_start):
        # This is an indexed lookup, not one extra marker per record/value in a crowded burst.
        values = (self._lookup(key), self._lookup(value), self._lookup(host), bucket_start, stamp, stamp,
                  _stored_id(identity))
        return self.store().execute(
            "SELECT 1 FROM windows_rows WHERE k=? AND value=? AND host=? AND ts>=? AND "
            "(ts<? OR (ts=? AND id<?)) UNION ALL SELECT 1 FROM windows_archive "
            "WHERE k=? AND value=? AND host=? AND ts>=? AND (ts<? OR (ts=? AND id<?)) LIMIT 1",
            (*values, *values)).fetchone() is not None

    def witnesses(self, key, end, seconds, count, *, distinct=False):
        inner = ("FROM (SELECT id,ts,value FROM windows_rows WHERE k=? AND ts>=? AND ts<=? UNION ALL "
                 "SELECT id,ts,value FROM windows_archive WHERE k=? AND ts>=? AND ts<=?) ")
        if distinct:
            # A self-join over the UNION view could materialize the hunt archive for every check.
            query = "SELECT MIN(id),MIN(ts) " + inner + "GROUP BY value ORDER BY MIN(ts),MIN(id) LIMIT ?"
        else:
            # GROUP BY id also prevents double counting if a failed expiry move left both copies readable.
            query = "SELECT id,MIN(ts) " + inner + "GROUP BY id ORDER BY MIN(ts),id LIMIT ?"
        interval = (self._lookup(key), end-seconds, end)
        return [(_event_id(identity), stamp) for identity, stamp in
                self.store().execute(query, (*interval, *interval, count))]

    def count(self, key):
        return self.store().execute("SELECT COUNT(DISTINCT id) FROM windows_all WHERE k=?", (key,)).fetchone()[0]

    def iterate(self):
        if self.ready:
            for key, identity, stamp, value, host in self.store().execute(
                    "SELECT k,id,ts,value,host FROM windows_all ORDER BY k,ts,id"):
                yield key, _event_id(identity), stamp, value, host

    def daily_groups(self, threshold):
        if self.ready:
            # Hunt-span catches low-and-slow breadth; both daily partitions still run independently.
            for offset in (0, 43200):
                yield from self.store().execute(
                    "SELECT k,CAST((ts-?)/86400 AS INTEGER),COUNT(DISTINCT value),? FROM windows_all "
                    "WHERE k LIKE '[\"daily-%' GROUP BY k,CAST((ts-?)/86400 AS INTEGER) "
                    "HAVING COUNT(DISTINCT value)>=? ORDER BY k", (offset, offset, offset, threshold))
            yield from self.store().execute(
                "SELECT k,NULL,COUNT(DISTINCT value),0 FROM windows_all WHERE k LIKE '[\"daily-%' "
                "GROUP BY k HAVING COUNT(DISTINCT value)>=? ORDER BY k", (threshold,))

    def daily_witnesses(self, key, day, threshold, offset=0):
        if day is None:
            end = self.store().execute("SELECT MAX(ts) FROM windows_all WHERE k=?", (key,)).fetchone()[0]
            return self.witnesses(key, end, float("inf"), threshold, distinct=True)
        return self.witnesses(key, (day+1)*86400+offset-0.000001, 86400-0.000001, threshold, distinct=True)
