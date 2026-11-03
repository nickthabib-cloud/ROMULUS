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
from collections import OrderedDict
from contextlib import contextmanager
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
        self._symbol_cache = OrderedDict()
        self._symbol_bytes = 0
        self._batching = False
        self._batch_refusal = None
        self._in_savepoint = False

    @contextmanager
    def batch(self):
        spill = self.store()
        spill.flush()
        budget = self.owner.state_budget()
        budget.check_free()
        pages = spill.db.execute("PRAGMA page_count").fetchone()[0]
        spill.db.execute(f"PRAGMA max_page_count={max(1, pages+budget.physical_allowance(self.account)//spill._page)}")
        self._batch_refusal = budget.new_key_reason(self.account)
        self._batching = True
        try:
            yield
        finally:
            spill.db.commit()
            self._batching = False
            spill.grew()
            self._charge()

    def room(self):
        # The SQLite page limit enforces each write inside this batch. Rechecking every
        # symbol/marker would repeat global admission work for every input record.
        if not self._batching:
            return super().room()
        if self._batch_refusal:
            self.owner.note_limit("windows_rows", "Correlation row growth is incomplete: " + self._batch_refusal)
        return not self._batch_refusal

    def _execute(self, statement, values=()):
        spill = self.store()
        return spill.db.execute(statement, values) if self._batching or self._in_savepoint else spill.execute(statement, values)

    def _cache(self, value, identity):
        cost = len(value.encode())+96
        if cost > 2**20:
            return
        previous = self._symbol_cache.pop(value, None)
        if previous is None:
            self._symbol_bytes += cost
        self._symbol_cache[value] = identity
        while len(self._symbol_cache) > 8192 or self._symbol_bytes > 2**20:
            oldest, _ = self._symbol_cache.popitem(last=False)
            self._symbol_bytes -= len(oldest.encode())+96

    def store(self):
        spill = self.owner.spill()
        if not self.ready:
            self.account = self.owner.state_budget().account(f"{self.owner.id}:windows_rows", strong=True)
            spill.budget.reclaim_citations(16*spill._page)
            spill.cap()
            try:
                self._schema(spill)
            except sqlite3.OperationalError as error:
                spill.db.rollback()
                raise spill.failed(error, account=self.account) from error
            finally:
                spill.grew()
            self.ready = True
            self._charge()
        return spill

    @staticmethod
    def _schema(spill):
        spill.db.execute("SAVEPOINT auth_schema")
        spill.db.execute("CREATE TABLE windows_symbols(id INTEGER PRIMARY KEY,value TEXT UNIQUE)")
        spill.db.execute("CREATE TABLE windows_refs(id BLOB PRIMARY KEY,target INTEGER,native TEXT,"
                         "fields BLOB,template INTEGER) WITHOUT ROWID")
        for table in ("windows_rows", "windows_archive"):
            spill.db.execute(f"CREATE TABLE {table}(k INTEGER,id BLOB,ts REAL,value INTEGER,host INTEGER,"
                             "PRIMARY KEY(k,id)) WITHOUT ROWID")
            spill.db.execute(f"CREATE INDEX {table}_time ON {table}(k,ts,id)")
            spill.db.execute(f"CREATE INDEX {table}_value ON {table}(k,value,host,ts)")
            spill.db.execute(f"CREATE INDEX {table}_identity ON {table}(id)")
        spill.db.execute("CREATE INDEX windows_rows_expiry ON windows_rows(ts)")
        spill.db.execute("CREATE VIEW windows_all AS SELECT k.value k,w.id,w.ts,v.value value,h.value host FROM "
                         "(SELECT * FROM windows_rows UNION ALL SELECT * FROM windows_archive) w "
                         "JOIN windows_symbols k ON k.id=w.k JOIN windows_symbols v ON v.id=w.value "
                         "JOIN windows_symbols h ON h.id=w.host")
        spill.db.execute("CREATE TABLE windows_marks(k TEXT PRIMARY KEY,value TEXT) WITHOUT ROWID")
        spill.db.execute("CREATE TABLE windows_accounts(k INTEGER,account INTEGER,PRIMARY KEY(k,account)) WITHOUT ROWID")
        spill.db.execute("CREATE TABLE windows_hosts(n INTEGER PRIMARY KEY,k INTEGER,host INTEGER,"
                         "first_id BLOB,first_ts REAL,revision INTEGER NOT NULL DEFAULT 0,UNIQUE(k,host))")
        spill.db.execute("RELEASE auth_schema")

    def _charge(self):
        # Charge allocated pages, including indexes and symbols, rather than a favorable payload estimate.
        db = self.owner.spill().db
        size = db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0]
        self.owner.state_budget().charge(self.account, size-self.account.used)

    def _reclaim_capacity(self):
        """An actual FULL write gets one retry after optional citation caches yield."""
        spill, budget = self.store(), self.owner.state_budget()
        spill.grew()
        self._charge()
        before = budget.physical_used
        budget.reclaim_citations(budget.disk_total, references=True)
        if budget.physical_used >= before:
            return False
        pages = spill.db.execute("PRAGMA page_count").fetchone()[0]
        spill.db.execute(f"PRAGMA max_page_count={max(1, pages+budget.physical_allowance(self.account)//spill._page)}")
        self._batch_refusal = budget.new_key_reason(self.account)
        return not self._batch_refusal

    def _write(self, statement, rows, *, retried=False):
        spill = self.store()
        budget = self.owner.state_budget()
        if self._batching:
            try:
                spill.db.executemany(statement, rows)
                if not self._in_savepoint:
                    spill.db.commit()
            except sqlite3.OperationalError as exc:
                spill.db.rollback()
                self._symbol_cache.clear()
                self._symbol_bytes = 0
                if "full" in str(exc).lower():
                    if not self._in_savepoint and not retried and self._reclaim_capacity():
                        return self._write(statement, rows, retried=True)
                    raise StateExhausted("authentication state reached its hunt byte allowance or volume reserve") from exc
                raise
            return
        budget.check_free()
        reason = budget.new_key_reason(self.account)
        if reason:
            raise StateExhausted(reason)
        available = budget.physical_allowance(self.account)
        headroom = budget.headroom()
        if headroom is not None:
            available = min(available, headroom)
        pages = spill.db.execute("PRAGMA page_count").fetchone()[0]
        spill.db.execute(f"PRAGMA max_page_count={pages+available//spill._page}")
        try:
            spill.db.executemany(statement, rows)
            if not self._in_savepoint:
                spill.db.commit()
        except sqlite3.OperationalError as exc:
            spill.db.rollback()
            self._symbol_cache.clear()
            self._symbol_bytes = 0
            if "full" in str(exc).lower():
                if not self._in_savepoint and not retried and self._reclaim_capacity():
                    return self._write(statement, rows, retried=True)
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
        identity = self.store().db.execute("SELECT last_insert_rowid()").fetchone()[0]
        self._cache(value, identity)
        return identity

    def _lookup(self, value):
        if value in self._symbol_cache:
            self._symbol_cache.move_to_end(value)
            return self._symbol_cache[value]
        row = self._execute("SELECT id FROM windows_symbols WHERE value=?", (value,)).fetchone()
        if row:
            self._cache(value, row[0])
        return row[0] if row else None

    def marked(self, key):
        return self.marker(key) is not None

    def marker(self, key):
        row = self._execute("SELECT value FROM windows_marks WHERE k=?", (key,)).fetchone()
        return row[0] if row else None

    def markers(self, prefix):
        yield from self._execute("SELECT k,value FROM windows_marks WHERE k>=? AND k<? ORDER BY k",
                                 (prefix, prefix+chr(0x10ffff)))

    def reset_markers(self, prefix):
        self._execute("DELETE FROM windows_marks WHERE k>=? AND k<?", (prefix, prefix+chr(0x10ffff)))

    def put(self, key, event, value="", *, retried=False):
        spill = self.store()
        key_id = self._lookup(key)
        if key_id is not None and self._execute(
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
        stored = False
        try:
            spill.db.commit()
            spill.db.execute("SAVEPOINT auth_record")
            self._in_savepoint = True
            if not self._execute("SELECT 1 FROM windows_refs WHERE id=?", (_stored_id(event.id),)).fetchone():
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
            # Keep the recorded identity even when qualification counts records rather than distinct values.
            # This dictionary entry is shared by repeated credentials and supports truthful aggregate totals.
            row = (self._symbol(key), _stored_id(event.id), stamp, self._symbol(value), self._symbol(event.host))
            self._write(f"INSERT INTO {table} VALUES(?,?,?,?,?)", [row])
            self._write("INSERT INTO windows_hosts(k,host,first_id,first_ts) VALUES(?,?,?,?) "
                        "ON CONFLICT(k,host) DO UPDATE SET first_id=excluded.first_id,first_ts=excluded.first_ts,"
                        "revision=windows_hosts.revision+1 "
                        "WHERE (excluded.first_ts,excluded.first_id)<(windows_hosts.first_ts,windows_hosts.first_id)",
                        [(row[0], row[4], row[1], stamp)])
            account = event.get("auth.target_account")
            if account:
                self._write("INSERT OR IGNORE INTO windows_accounts VALUES(?,?)",
                            [(row[0], self._symbol(json.dumps(account)))])
            spill.db.execute("RELEASE auth_record")
            self._in_savepoint = False
            stored = True
            if stamp > self.watermark:
                # Rows move, rather than being forgotten; the archive also catches late cross-target windows.
                # Commit bounded moves so the in-memory rollback journal cannot grow with a whole
                # high-volume time window. A crash can leave both copies; readers deduplicate ids.
                while expired := self._execute("SELECT * FROM windows_rows WHERE ts<? ORDER BY ts,k,id LIMIT 256",
                                               (cutoff,)).fetchall():
                    spill.db.execute("SAVEPOINT auth_expiry")
                    self._in_savepoint = True
                    self._write("INSERT OR IGNORE INTO windows_archive VALUES(?,?,?,?,?)", expired)
                    self._write("DELETE FROM windows_rows WHERE k=? AND id=?", [(row[0], row[1]) for row in expired])
                    spill.db.execute("RELEASE auth_expiry")
                    self._in_savepoint = False
                self.watermark = stamp
        except StateExhausted as exc:
            self._in_savepoint = False
            if stored:
                # The record's savepoint has committed. Expiry is optional maintenance;
                # active rows remain replayable even when an archive move cannot grow.
                self.owner.note_limit("windows_expiry", f"Authentication archive maintenance deferred: {exc}")
                self._charge()
                return True
            if not retried and self._reclaim_capacity():
                return self.put(key, event, value, retried=True)
            self._refuse(event, f"An authentication correlation key could not be written: {exc}")
            self._charge()
            return False
        if not self._batching:
            self._charge()
        return True

    def compact(self, identities):
        """Rebuild only cited, recorded fields. The source body is fetched at publication, if available."""
        out = []
        for identity in identities:
            row = self._execute(
                "SELECT r.target,r.native,r.fields,r.template,w.ts,w.host FROM windows_refs r JOIN "
                "(SELECT id,ts,host FROM windows_rows UNION ALL SELECT id,ts,host FROM windows_archive) w "
                "ON w.id=r.id WHERE r.id=? LIMIT 1", (_stored_id(identity),)).fetchone()
            if row is None:
                continue
            target, native, blob, template, stamp, host = row
            def symbol(number):
                return self._execute("SELECT value FROM windows_symbols WHERE id=?", (number,)).fetchone()[0]
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
            if not self._batching:
                self._charge()
        except StateExhausted as exc:
            self.owner.note_limit("windows_marks", f"Correlation revision state could not be retained: {exc}")

    def first(self, key):
        if self.marked(key):
            return False
        if self.room():
            try:
                self._write("INSERT INTO windows_marks VALUES(?,?)", [(key, "")])
                if not self._batching:
                    self._charge()
            except StateExhausted as exc:
                self.owner.note_limit("windows_marks", f"Correlation dedup markers could not be retained: {exc}")
        return True

    def prior_value(self, key, stamp, value, host, identity, bucket_start):
        # This is an indexed lookup, not one extra marker per record/value in a crowded burst.
        values = (self._lookup(key), self._lookup(value), self._lookup(host), bucket_start, stamp, stamp,
                  _stored_id(identity))
        return self._execute(
            "SELECT 1 FROM windows_rows WHERE k=? AND value=? AND host=? AND ts>=? AND "
            "(ts<? OR (ts=? AND id<?)) UNION ALL SELECT 1 FROM windows_archive "
            "WHERE k=? AND value=? AND host=? AND ts>=? AND (ts<? OR (ts=? AND id<?)) LIMIT 1",
            (*values, *values)).fetchone() is not None

    def witnesses(self, key, end, seconds, count, *, distinct=False, latest=False):
        inner = ("FROM (SELECT id,ts,value FROM windows_rows WHERE k=? AND ts>=? AND ts<=? UNION ALL "
                 "SELECT id,ts,value FROM windows_archive WHERE k=? AND ts>=? AND ts<=?) ")
        if latest and distinct:
            query = ("SELECT id,ts FROM (SELECT id,ts,ROW_NUMBER() OVER(PARTITION BY value ORDER BY ts DESC,id DESC) r "
                     + inner + ") WHERE r=1 ORDER BY ts DESC,id DESC LIMIT ?")
        elif latest:
            query = "SELECT id,MAX(ts) " + inner + "GROUP BY id ORDER BY MAX(ts) DESC,id DESC LIMIT ?"
        elif distinct:
            # A self-join over the UNION view could materialize the hunt archive for every check.
            query = "SELECT MIN(id),MIN(ts) " + inner + "GROUP BY value ORDER BY MIN(ts),MIN(id) LIMIT ?"
        else:
            # GROUP BY id also prevents double counting if a failed expiry move left both copies readable.
            query = "SELECT id,MIN(ts) " + inner + "GROUP BY id ORDER BY MIN(ts),id LIMIT ?"
        interval = (self._lookup(key), end-seconds, end)
        return [(_event_id(identity), stamp) for identity, stamp in
                self._execute(query, (*interval, *interval, count))]

    def count(self, key):
        return self._execute("SELECT COUNT(DISTINCT id) FROM windows_all WHERE k=?", (key,)).fetchone()[0]

    def totals(self, key):
        total, values = self._execute("SELECT COUNT(DISTINCT id),COUNT(DISTINCT value) FROM windows_all WHERE k=?",
                                      (key,)).fetchone()
        accounts = self._execute("SELECT COUNT(*) FROM windows_accounts WHERE k=?", (self._lookup(key),)).fetchone()[0]
        return total, values, accounts

    def host_checkpoint(self, key):
        return self._execute("SELECT COUNT(*),COALESCE(MAX(n),0),COALESCE(SUM(revision),0) FROM windows_hosts WHERE k=?",
                             (self._lookup(key),)).fetchone()

    def hosts(self, key, through):
        # A publication can wait until the current input batch ends. Its sequence fence keeps
        # later hosts out of that earlier snapshot without materializing the whole host list.
        for host, identity in self._execute(
                "SELECT s.value,h.first_id FROM windows_hosts h JOIN windows_symbols s ON s.id=h.host "
                "WHERE h.k=? AND h.n<=? ORDER BY s.value", (self._lookup(key), through)):
            yield host, _event_id(identity)

    def iterate(self):
        if self.ready:
            for key, identity, stamp, value, host in self._execute(
                    "SELECT k,id,ts,value,host FROM windows_all ORDER BY k,ts,id"):
                yield key, _event_id(identity), stamp, value, host

    def daily_groups(self, threshold):
        if self.ready:
            # Hunt-span catches low-and-slow breadth; both daily partitions still run independently.
            for offset in (0, 43200):
                yield from self._execute(
                    "SELECT k,CAST((ts-?)/86400 AS INTEGER),COUNT(DISTINCT value),? FROM windows_all "
                    "WHERE k LIKE '[\"daily-%' GROUP BY k,CAST((ts-?)/86400 AS INTEGER) "
                    "HAVING COUNT(DISTINCT value)>=? ORDER BY k", (offset, offset, offset, threshold))
            yield from self._execute(
                "SELECT k,NULL,COUNT(DISTINCT value),0 FROM windows_all WHERE k LIKE '[\"daily-%' "
                "GROUP BY k HAVING COUNT(DISTINCT value)>=? ORDER BY k", (threshold,))

    def daily_witnesses(self, key, day, threshold, offset=0):
        if day is None:
            end = self._execute("SELECT MAX(ts) FROM windows_all WHERE k=?", (key,)).fetchone()[0]
            return self.witnesses(key, end, float("inf"), threshold, distinct=True, latest=True)
        return self.witnesses(key, (day+1)*86400+offset-0.000001, 86400-0.000001, threshold, distinct=True, latest=True)
