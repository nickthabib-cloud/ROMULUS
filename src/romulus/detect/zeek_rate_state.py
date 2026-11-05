"""Disk-backed raw-reference windows with incremental live state and ordered late replay.

Only attempt rows contribute counts. Success rows can strengthen a qualifying
preceding window. Late rows and later raw-reference additions to an older event
are retained for finalize replay; they never rewrite the forward window.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import ClassVar

from romulus.detect.base import LANES, Match, Playbook, pf
from romulus.detect.bounded import StateExhausted, register_store
from romulus.evidence.typed import RawRef, TypedEvent
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

_SAMPLE = 3
_BATCH_WRITES = 256
_BATCH_BYTES = 1024 * 1024
_BATCH_KEYS = 256
_ROW_CHUNK = 128
_PARTIAL_CITATIONS = (
    "Citation coverage is partial: the sample retains at most three events and three native references per event; "
    "counted attempt references are deduplicated independently of this citation sample."
)


def _bytes(*values):
    return sum(len(value) if isinstance(value, bytes) else len(str(value).encode()) for value in values)


class _RecordingDB:
    """A bounded transaction's successful mutations, for SQLite FULL rollback recovery.

    Queries run on the live connection. Only concrete SQL parameters are retained;
    no event objects, selection closures or matches live in this journal.
    """

    def __init__(self, db):
        self.db, self.statements, self.size = db, [], 0

    def execute(self, sql, params=()):
        result = self.db.execute(sql, params)
        if sql.split(None, 1)[0].upper() in {"INSERT", "UPDATE", "DELETE"}:
            self.statements.append((sql, params))
            self.size += _bytes(sql, *params)
        return result


class _WindowRows:
    """Retained history and rebuildable indexed counters share the hunt's spill budget."""

    schema = (
        "CREATE TABLE history(k TEXT,id TEXT,ts REAL,member TEXT,role TEXT,weight INTEGER,payload BLOB,PRIMARY KEY(k,id))",
        "CREATE INDEX history_time ON history(k,ts,id)",
        "CREATE TABLE success_proofs(k TEXT,id TEXT,proof TEXT,PRIMARY KEY(k,id))",
        "CREATE TABLE raw_refs(k TEXT,ref TEXT,id TEXT,target TEXT,native_id TEXT,digest TEXT,priority INTEGER,PRIMARY KEY(k,ref))",
        "CREATE INDEX raw_refs_event ON raw_refs(k,id,priority,ref)",
        "CREATE TABLE live(k TEXT PRIMARY KEY,watermark REAL,total INTEGER,distinct_n INTEGER)",
        "CREATE TABLE active(k TEXT,id TEXT,ts REAL,member TEXT,weight INTEGER,PRIMARY KEY(k,id))",
        "CREATE INDEX active_time ON active(k,ts,id)",
        "CREATE TABLE members(k TEXT,member TEXT,n INTEGER,PRIMARY KEY(k,member))",
        "CREATE TABLE marks(k TEXT PRIMARY KEY,lane INTEGER,summary TEXT)",
        "CREATE TABLE episodes(k TEXT PRIMARY KEY,body TEXT)",
    )

    def __init__(self, owner):
        self.owner, self.ready, self.account = owner, False, None
        self.derived_bytes = 0
        self.pending, self.pending_bytes = [], 0
        self.recovering = False
        register_store(owner, self)

    def room(self, kind):
        reason = self.owner.state_budget().new_key_reason(self.account)
        if reason:
            self.owner.note_limit("zeek_window_" + kind, f"Zeek window {kind} growth is incomplete: {reason}")
        return not reason

    def store(self):
        spill = self.owner.spill()
        if self.ready:
            # Reads must see every accepted operation before deriving an insert
            # or update; recovering only inside write would leave stale closures.
            if self.recovering:
                self._restore(spill)
            return spill
        if self.account is None:
            self.account = self.owner.state_budget().account(self.owner.id + ":zeek_window", strong=True)
        if not self.room("schema"):
            raise StateExhausted("the Zeek window schema could not be retained")
        spill.cap()
        try:
            spill.db.execute("SAVEPOINT zeek_window_schema")
            for statement in self.schema:
                spill.db.execute(statement)
            spill.db.execute("RELEASE zeek_window_schema")
            self.ready = True
        except sqlite3.OperationalError as error:
            spill.db.rollback()
            raise spill.failed(error, account=self.account) from error
        finally:
            spill.grew()
        return spill

    def flush(self):
        """Commit the accepted bounded prefix before publication or partition exit."""
        if not self.ready or not self.pending:
            return
        spill = self.owner.spill()
        if self.recovering:
            self._restore(spill)
            return
        try:
            spill.db.commit()
        except sqlite3.OperationalError as error:
            self.owner.note_limit('zeek_window_commit', f'Zeek window commit failed; accepted operations require recovery: {error}')
            self._restore(spill)
            return
        self.pending.clear()
        self.pending_bytes = 0
        spill.grew()

    def _restore(self, spill):
        # SQLITE_FULL can roll back the *whole* transaction, not just its last
        # statement. Replay only successful operations under the same page cap.
        # They already fitted that ceiling; no failing operation is journaled.
        spill.db.rollback()
        self.recovering = True
        try:
            while self.pending:
                statements = self.pending[0]
                for sql, params in statements:
                    spill.db.execute(sql, params)
                # Recovery is exceptional: commit each accepted operation so a
                # later recovery failure cannot discard its restored prefix.
                spill.db.commit()
                self.pending.pop(0)
                self.pending_bytes -= sum(_bytes(sql, *params) for sql, params in statements)
            self.recovering = False
            self.pending_bytes = 0
        except sqlite3.OperationalError as error:
            spill.db.rollback()
            self.owner.note_limit('zeek_window_commit_recovery', f'Zeek window commit recovery is incomplete; its bounded journal is retained: {error}')
            failure = spill.failed(error, account=self.account)
            raise (failure if isinstance(failure, StateExhausted) else StateExhausted(str(failure))) from error
        finally:
            spill.grew()

    def write(self, kind, operation, *, growing=True):
        spill = self.store()
        if self.recovering:
            self._restore(spill)
        if growing and not self.room(kind):
            raise StateExhausted(f"the Zeek window {kind} state could not grow")
        if self.owner.state_budget().hard:
            raise StateExhausted(self.owner.state_budget().hard)
        while True:
            if not self.pending:
                # Volume checks, citation reclamation and heartbeat syscalls
                # occur at bounded transaction boundaries, never per row.
                self.owner.state_budget().reclaim_citations(4 * spill._page)
                spill.cap()
                spill.db.execute("BEGIN")
            recording = _RecordingDB(spill.db)
            try:
                result, delta = operation(recording)
                break
            except sqlite3.OperationalError as error:
                self._restore(spill)
                if ("full" in str(error).lower() and self.owner.state_budget().reclaim_citations_step(
                        writer_db=spill.db, writer_path=spill.path, writer_page=spill._page,
                        writer_cap=spill._cap_global, writer_current=lambda: (spill.db, spill.path))):
                    continue
                raise spill.failed(error, account=self.account) from error
            except BaseException:
                self._restore(spill)
                raise
        self.pending.append(recording.statements)
        self.pending_bytes += recording.size
        self.owner.state_budget().charge(self.account, delta)
        if kind == "derived":
            self.derived_bytes += delta
        if len(self.pending) >= _BATCH_WRITES or self.pending_bytes >= _BATCH_BYTES:
            self.flush()
        return result

    def put(self, key, event, member, role):
        stored = None
        for offset in range(0, len(event.raw), _ROW_CHUNK):
            row = event.model_copy(update={"raw": event.raw[offset:offset + _ROW_CHUNK]})
            try:
                accepted = self._put(key, row, member, role)
            except StateExhausted as error:
                if stored is None:
                    raise
                self.owner.refuse("zeek_window_history", f"Zeek reference retention is incomplete; accepted references remain available: {error}")
                return stored
            if accepted is not None:
                stored = accepted
        return stored

    def _put(self, key, event, member, role):
        db = self.store().db
        previous = db.execute("SELECT ts,member,role,weight,payload FROM history WHERE k=? AND id=?",
                              (key, event.id)).fetchone()
        if previous and previous[:3] != (event.ts.timestamp(), member, role):
            self.owner.refuse("zeek_window_conflict", "A canonical Zeek event id had conflicting time, member or role; its update is unresolved.")
            return None
        if not any(not db.execute("SELECT 1 FROM raw_refs WHERE k=? AND ref=?", (key, ref.key)).fetchone()
                   for ref in event.raw if ref.target and ref.native_id):
            return None

        def insert(db):
            delta, weight = 0, previous[3] if previous else 0
            if previous:
                canonical = self.event(key, event.id, previous[0], role, previous[4])
            else:
                canonical = self.owner.compact_success(event) if role == "success" else self.owner.compact(event)
            if previous is None:
                payload = None if role == "success" else compact_event(canonical)
                db.execute("INSERT INTO history VALUES(?,?,?,?,?,?,?)",
                           (key, event.id, event.ts.timestamp(), member, role, 0, payload))
                delta += _bytes(key, event.id, member, role, payload) + 128
                if role == "success":
                    # This is a minimal proof, not a retained TypedEvent body:
                    # id/time/member live in history and native refs are deduped
                    # separately. Only explicitly declared success facts remain.
                    proof = json.dumps([canonical.family, canonical.host, canonical.outcome, canonical.normalizer,
                                        [[name, fact.value, fact.origin] for name, fact in canonical.fields.items()],
                                        canonical.caveats], separators=(",", ":"))
                    db.execute("INSERT INTO success_proofs VALUES(?,?,?)", (key, event.id, proof))
                    delta += _bytes(key, event.id, proof) + 96
            else:
                payload = previous[4]
            for ref in event.raw:
                if not ref.target or not ref.native_id:
                    continue
                priority = 0 if any(fact.origin.startswith(ref.native_id + ":")
                                    for fact in canonical.fields.values()) else 1
                added = db.execute("INSERT OR IGNORE INTO raw_refs VALUES(?,?,?,?,?,?,?)",
                                   (key, ref.key, event.id, ref.target, ref.native_id, ref.digest, priority)).rowcount
                if added:
                    weight += 1
                    delta += _bytes(key, ref.key, event.id, ref.target, ref.native_id, ref.digest) + 128
            refs = [RawRef(target=target, native_id=native, digest=digest) for target, native, digest in db.execute(
                "SELECT target,native_id,digest FROM raw_refs WHERE k=? AND id=? ORDER BY priority,ref LIMIT ?",
                (key, event.id, _SAMPLE))]
            canonical = canonical.model_copy(update={"raw": refs})
            packed = None if role == "success" else compact_event(canonical)
            delta += len(packed or b'') - len(payload or b'')
            db.execute("UPDATE history SET weight=?,payload=? WHERE k=? AND id=?", (weight, packed, key, event.id))
            if db.execute("INSERT OR IGNORE INTO marks(k,lane) VALUES(?,?)", (key, len(LANES))).rowcount:
                delta += _bytes(key) + 96
            return (canonical, weight), delta

        return self.write("history", insert)

    def event(self, key, identity, stamp, role, payload):
        if role != "success":
            return expand_event(payload)
        db = self.store().db
        family, host, outcome, normalizer, facts, caveats = json.loads(db.execute(
            "SELECT proof FROM success_proofs WHERE k=? AND id=?", (key, identity)).fetchone()[0])
        refs = [RawRef(target=target, native_id=native, digest=digest) for target, native, digest in db.execute(
            "SELECT target,native_id,digest FROM raw_refs WHERE k=? AND id=? ORDER BY priority,ref LIMIT ?",
            (key, identity, _SAMPLE))]
        return TypedEvent(id=identity, ts=datetime.fromtimestamp(stamp, UTC), family=family, host=host,
                          outcome=outcome, normalizer=normalizer, caveats=caveats, raw=refs,
                          fields={name: {"value": value, "origin": origin} for name, value, origin in facts})

    def advance(self, key, event, member, role, weight):
        db = self.store().db
        previous = db.execute("SELECT watermark,total,distinct_n FROM live WHERE k=?", (key,)).fetchone()
        stamp = event.ts.timestamp()
        if previous and stamp < previous[0]:
            return None
        if previous:
            self._expire(key, stamp)
            previous = db.execute("SELECT watermark,total,distinct_n FROM live WHERE k=?", (key,)).fetchone()

        def update(db):
            total, distinct = previous[1:] if previous else (0, 0)
            delta = 0 if previous else _bytes(key) + 128
            if previous is None:
                db.execute("INSERT INTO live VALUES(?,?,0,0)", (key, stamp))
            below = (distinct if self.owner.distinct else total) < self.owner.threshold
            if role == "attempt":
                active = db.execute("SELECT weight FROM active WHERE k=? AND id=?", (key, event.id)).fetchone()
                if active:
                    total += weight - active[0]
                    db.execute("UPDATE active SET weight=? WHERE k=? AND id=?", (weight, key, event.id))
                else:
                    db.execute("INSERT INTO active VALUES(?,?,?,?,?)", (key, event.id, stamp, member, weight))
                    delta += _bytes(key, event.id, member) + 128
                    exists = db.execute("SELECT n FROM members WHERE k=? AND member=?", (key, member)).fetchone()
                    if exists:
                        db.execute("UPDATE members SET n=n+1 WHERE k=? AND member=?", (key, member))
                    else:
                        db.execute("INSERT INTO members VALUES(?,?,1)", (key, member))
                        delta += _bytes(key, member) + 96
                        distinct += 1
                    total += weight
            db.execute("UPDATE live SET watermark=?,total=?,distinct_n=? WHERE k=?", (stamp, total, distinct, key))
            return (total, distinct, below), delta

        return self.write("derived", update)

    def _expire(self, key, stamp):
        db = self.store().db
        while True:
            expired = db.execute("SELECT id,member,weight FROM active WHERE k=? AND ts<? ORDER BY ts,id LIMIT ?",
                                 (key, stamp - self.owner.seconds, _ROW_CHUNK)).fetchall()
            if not expired:
                return

            def remove(db, expired=expired):
                total, distinct = db.execute("SELECT total,distinct_n FROM live WHERE k=?", (key,)).fetchone()
                delta = 0
                for identity, member, weight in expired:
                    total -= weight
                    db.execute("DELETE FROM active WHERE k=? AND id=?", (key, identity))
                    delta -= _bytes(key, identity, member) + 128
                    count = db.execute("SELECT n FROM members WHERE k=? AND member=?", (key, member)).fetchone()[0]
                    if count == 1:
                        db.execute("DELETE FROM members WHERE k=? AND member=?", (key, member))
                        distinct -= 1
                        delta -= _bytes(key, member) + 96
                    else:
                        db.execute("UPDATE members SET n=n-1 WHERE k=? AND member=?", (key, member))
                # A refused later chunk must not let an older forward event use
                # the partially expired view. Ordered replay retains all history.
                db.execute("UPDATE live SET watermark=?,total=?,distinct_n=? WHERE k=?", (stamp, total, distinct, key))
                return None, delta

            self.write("derived", remove, growing=False)

    def clear_derived(self):
        def clear(db):
            for name in ("active", "members", "live", "episodes"):
                db.execute("DELETE FROM " + name)
            return None, -self.derived_bytes
        self.write("derived", clear, growing=False)

    def close(self):
        if self.account:
            self.owner.state_budget().charge(self.account, -self.account.used)
        self.owner.close_spill()
        self.account, self.ready, self.derived_bytes = None, False, 0
        self.pending.clear()
        self.pending_bytes, self.recovering = 0, False


class ZeekWindowRule(Playbook, ABC):
    """Subclass with typed selection, a window threshold and an evidence-supported description.

    `citation_fields` must include every typed fact read by `describe`, because
    finalize reads compact canonical facts. `select` owns sensor/source keying.
    Counts are attempt-only; success never contributes toward a threshold.
    """

    kind = "aggregate"
    claim_type = "aggregate_observation"
    anchor_class = "network_observation"
    state_slice = "strong"
    assures_negative = False
    positive_only_reason = "Zeek window observations are positive-only; missing outcomes and partial sensor visibility cannot establish absence."
    seconds: ClassVar[float] = 60
    threshold: ClassVar[int] = 1
    distinct: ClassVar[bool] = False
    citation_fields: ClassVar[tuple[str, ...]] = ()
    # Success selection/account proof is deliberately separate from potentially
    # large attempt citation facts. Subclasses declare facts needed by describe.
    success_fields: ClassVar[tuple[str, ...]] = ()
    success_requires_member: ClassVar[bool] = False

    def __init__(self):
        super().__init__()
        if self.seconds <= 0 or self.threshold < 1:
            raise ValueError("Zeek windows require positive seconds and a threshold of at least one")
        self.rows = _WindowRows(self)
        self.load = lambda _ids: []

    @abstractmethod
    def select(self, event: TypedEvent) -> tuple[tuple, str, str] | None:
        """Return (key, member, attempt|success) using typed fields only."""

    @abstractmethod
    def describe(self, event: TypedEvent, total_refs: int, distinct_members: int, role: str) -> tuple[str, str, tuple] | None:
        """Return (lane, claim, notes) for a qualifying window, or no observation."""

    def compact(self, event):
        fields = {*self.required_fields, *self.citation_fields}
        # Never copy a hunt-sized reference set into the retained event body.
        return event.model_copy(update={"fields": {name: fact for name, fact in event.fields.items() if name in fields},
                                        "raw": [], "caveats": list(dict.fromkeys([*event.caveats, COMPACT_CITATION_NOTE]))})

    def compact_success(self, event):
        fields = {*self.required_fields, *self.success_fields}
        return event.model_copy(update={"fields": {name: fact for name, fact in event.fields.items() if name in fields},
                                        "raw": [], "caveats": list(dict.fromkeys([*event.caveats, COMPACT_CITATION_NOTE]))})

    def consume(self, events):
        try:
            for match in self._consume(events):
                self.rows.flush()
                yield match
        finally:
            self.rows.flush()

    def _consume(self, events):
        touched = set()
        for event in sorted(events, key=lambda item: (item.ts, item.id)):
            if event.family not in self.families or not event.normalizer.startswith("zeek-ecs@"):
                continue
            if not self._events_pre_scoped:
                self.os_applicable += 1
            if (any(event.get(name) in (None, "", [], {}) for name in self.required_fields)
                    or not any(ref.target and ref.native_id for ref in event.raw)):
                self.missing_required += 1
                continue
            self.evaluated += 1
            selection = self.select(event)
            if selection is None:
                continue
            key, member, role = selection
            if not isinstance(key, tuple) or not isinstance(member, str) or role not in {"attempt", "success"}:
                raise ValueError("Zeek select must return a tuple key, text member and attempt|success role")
            key = json.dumps(key, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            try:
                stored = self.rows.put(key, event, member, role)
            except StateExhausted as error:
                kind = "history" if self.rows.ready else "schema"
                self.refuse("zeek_window_" + kind, f"Zeek window {kind} retention is incomplete: {error}")
                continue
            if stored is None:
                continue
            canonical, weight = stored
            touched.add(key)
            yield from self._accepted_forward(key, canonical, member, role, weight)
            if len(touched) >= _BATCH_KEYS:
                for touched_key in sorted(touched):
                    match = self._emit_episode(touched_key, force=True)
                    if match is not None:
                        yield match
                touched.clear()
        for key in sorted(touched):
            match = self._emit_episode(key, force=True)
            if match is not None:
                yield match

    def _accepted_forward(self, key, event, member, role, weight):
        try:
            yield from self._forward(key, event, member, role, weight)
        except StateExhausted as error:
            self.refuse("zeek_window_derived", f"Zeek episode state is incomplete; accepted history remains available: {error}")

    def _forward(self, key, event, member, role, weight):
        try:
            counts = self.rows.advance(key, event, member, role, weight)
        except StateExhausted as error:
            self.refuse("zeek_window_derived", f"Zeek window derived state is incomplete; retained history remains available: {error}")
            # A single accepted event may already prove a threshold regardless
            # of other context. Refusing a derived index must not delay it.
            if role == "attempt" and (1 if self.distinct else weight) >= self.threshold:
                decision = self.describe(event, weight, 1, role)
                if decision is not None:
                    match = self._single_publish(key, event, *decision)
                    if match is not None:
                        match.notes.append("Counts are lower bounds supported by this event's accepted references; other retained window context was not counted because derived state was unavailable.")
                        yield match
            return
        if counts is None:
            return
        total, distinct, below = counts
        summary_error = None
        if below:
            row = self.rows.store().db.execute("SELECT body FROM episodes WHERE k=?", (key,)).fetchone()
            if row:
                body = json.loads(row[0])
                body['active'] = False
                try:
                    self._save_episode(key, body, row[0])
                except StateExhausted as error:
                    summary_error = error
                    self.note_limit('zeek_window_episodes', f'Episode summary retention is partial: {error}')
        if (distinct if self.distinct else total) < self.threshold:
            return
        if role == "success":
            latest = self.rows.store().db.execute("SELECT ts FROM active WHERE k=? ORDER BY ts DESC,id DESC LIMIT 1",
                                                  (key,)).fetchone()
            # Equal timestamps do not establish that success followed attempts.
            if latest is None or latest[0] >= event.ts.timestamp():
                return
            if self.success_requires_member and (not member or not self.rows.store().db.execute(
                    'SELECT 1 FROM members WHERE k=? AND member=?', (key, member)).fetchone()):
                role = 'unrelated_success'
        decision = self.describe(event, total, distinct, role)
        if decision is not None:
            try:
                if summary_error is not None:
                    raise summary_error
                self._record_episode(key, event, total, distinct, role, member, decision)
                match = self._emit_episode(key)
            except StateExhausted as error:
                self.note_limit('zeek_window_episodes', f'Episode summary retention is partial: {error}')
                match = self._single_publish(key, event, *decision)
                if match is not None:
                    match.notes.append('Episode summary storage is partial; this positive uses the accepted current window counts without claiming a complete episode or peak summary.')
            if match is not None:
                yield match

    def _save_episode(self, key, body, previous):
        packed = json.dumps(body, sort_keys=True, separators=(",", ":"))
        def save(db):
            db.execute("INSERT OR REPLACE INTO episodes VALUES(?,?)", (key, packed))
            return None, len(packed) - len(previous or '') + (0 if previous else len(key)+96)
        self.rows.write('derived', save)

    def _record_episode(self, key, event, total, distinct, role, member, decision):
        lane, _claim, notes = decision
        if lane not in LANES:
            raise ValueError('Zeek describe returned an unsupported lane')
        row = self.rows.store().db.execute('SELECT body FROM episodes WHERE k=?', (key,)).fetchone()
        old = row[0] if row else None
        body = json.loads(old) if old else {'active':False, 'episodes':0, 'peak':0,
            'lane':len(LANES), 'success':None, 'success_member':None}
        stamp = event.ts.timestamp()
        if not body['active']:
            body['episodes'] += 1
            body['active'] = True
        if 'first' not in body:
            body['first'] = stamp
            body['first_event'] = compact_event(event).hex()
        body['last'] = stamp
        metric = distinct if self.distinct else total
        if metric > body['peak']:
            body.update(peak=metric, total=total, distinct=distinct, peak_ts=stamp,
                        peak_event=compact_event(event).hex(), notes=list(notes))
        rank = LANES.index(lane)
        if role == 'unrelated_success' and not body.get('other_success'):
            body['other_success'] = compact_event(event).hex()
            body['other_success_member'] = member
        if role == 'success' and rank < body['lane']:
            body['success'] = compact_event(event).hex()
            body['success_member'] = member
        body['lane'] = min(body['lane'], rank)
        self._save_episode(key, body, old)

    def _emit_episode(self, key, *, force=False):
        db = self.rows.store().db
        row = db.execute('SELECT body FROM episodes WHERE k=?', (key,)).fetchone()
        if row is None:
            return None
        body = json.loads(row[0])
        previous, digest = db.execute('SELECT lane,summary FROM marks WHERE k=?', (key,)).fetchone()
        # A summary refused during promotion still contains the weaker episode.
        # Preserve the fallback's stronger native witness until replay rebuilds it.
        if previous < body['lane']:
            return None
        # Replay may temporarily reconstruct only a prefix of an already published key.
        if not force and previous <= body['lane']:
            return None
        peak = expand_event(bytes.fromhex(body['peak_event']))
        decision = self.describe(peak, body['total'], body['distinct'], 'attempt')
        if decision is None:
            return None
        _lane, claim, notes = decision
        metric = 'distinct members' if self.distinct else 'attempt references'
        claim += (f" Across {body['episodes']} qualifying episode{'s' if body['episodes'] != 1 else ''}; "
                  f"peak {body['peak']} {metric} in one window.")
        samples = [expand_event(bytes.fromhex(body['first_event'])), peak]
        if body.get('success'):
            success = expand_event(bytes.fromhex(body['success']))
            samples.append(success)
            claim += f" A qualifying episode also had a later recorded authentication success for {body['success_member']}."
        elif body.get('other_success'):
            samples.append(expand_event(bytes.fromhex(body['other_success'])))
        if body.get('other_success'):
            notes = (*notes, 'A recorded success was not among the active sprayed accounts; it is unrelated to the spray membership and does not strengthen its lane.')
        iso = lambda stamp: datetime.fromtimestamp(stamp, UTC).isoformat()
        summaries = [f"First qualifying window: {iso(body['first']-self.seconds)} through {iso(body['first'])}.",
                     f"Last qualifying window: {iso(body['last']-self.seconds)} through {iso(body['last'])}.",
                     f"Peak qualifying window: {iso(body['peak_ts']-self.seconds)} through {iso(body['peak_ts'])}."]
        lane = LANES[min(previous, body['lane'])]
        identity = self.id + '|zeek-window|' + hashlib.sha256(key.encode()).hexdigest()
        sampled = list({event.id:event for event in samples}.values())
        fingerprint = json.dumps([lane, claim, summaries, [event.id for event in sampled]], sort_keys=True)
        if digest == fingerprint:
            return None
        result = Match(self.id, claim, self.claim_type, sampled,
            [pf(event, name) for event in sampled for name in sorted(event.fields)],
            peak.ts, 'high' if lane in {'urgent','high'} else self.severity, lane, 'medium', peak.entities(),
            [*notes, *summaries, _PARTIAL_CITATIONS, 'ATT&CK context (not proof): '+', '.join(self.attack)],
            group_key=identity, bounded_revision=True,
            revision_reason='Later qualifying episodes or a larger peak revise this source observation.' if digest else '')
        def mark(db):
            db.execute('UPDATE marks SET lane=?,summary=? WHERE k=?', (LANES.index(lane),fingerprint,key))
            return None, len(fingerprint)-len(digest or '')
        try:
            self.rows.write('marks',mark,growing=False)
        except StateExhausted as error:
            self.note_limit('zeek_window_marks',f'Zeek episode publication state is incomplete: {error}')
            result.notes.append('Publication state could not be retained; stable source identity is preserved.')
        return result

    def _single_publish(self, key, event, lane, claim, notes):
        if lane not in LANES:
            raise ValueError("Zeek describe returned an unsupported lane")
        spill = self.rows.store()
        previous = spill.db.execute("SELECT lane FROM marks WHERE k=?", (key,)).fetchone()[0]
        rank = LANES.index(lane)
        if rank >= previous:
            return None
        sampled = [event]
        for order in ("ASC", "DESC"):
            placeholders = ",".join("?" for _ in sampled)
            row = spill.db.execute(
                "SELECT h.payload FROM active a JOIN history h ON h.k=a.k AND h.id=a.id "
                f"WHERE a.k=? AND a.id NOT IN ({placeholders}) ORDER BY a.ts {order},a.id ASC LIMIT 1",
                (key, *(item.id for item in sampled))).fetchone()
            if row:
                sampled.append(expand_event(row[0]))
        sampled.sort(key=lambda item: (item.ts, item.id))
        # A loader may restore stage-held facts, but ids and counted canonical
        # fields stay those of the retained event, and reference samples stay bounded.
        for index, compact in enumerate(sampled):
            loaded = next((item for item in self.load([compact.id]) if item.id == compact.id), None)
            if (loaded is not None and loaded.ts == compact.ts and loaded.normalizer == compact.normalizer
                    and loaded.host == compact.host and loaded.outcome == compact.outcome
                    and all(loaded.fields.get(name) == fact for name, fact in compact.fields.items())):
                sampled[index] = loaded.model_copy(update={"fields": compact.fields, "raw": compact.raw,
                                                          "caveats": compact.caveats})
        identity = self.id + "|zeek-window|" + hashlib.sha256(key.encode()).hexdigest()
        result = Match(self.id, claim, self.claim_type, sampled,
                       [pf(item, name) for item in sampled for name in sorted(item.fields)], event.ts,
                       "high" if lane in {"urgent", "high"} else self.severity, lane, "medium", event.entities(),
                       [*notes, _PARTIAL_CITATIONS, "ATT&CK context (not proof): " + ", ".join(self.attack)],
                       group_key=identity, bounded_revision=True,
                       revision_reason="A later qualifying window strengthens this Zeek observation." if previous < len(LANES) else "")

        def mark(db):
            db.execute("UPDATE marks SET lane=? WHERE k=?", (rank, key))
            return None, 0

        try:
            self.rows.write("marks", mark, growing=False)
        except StateExhausted as error:
            self.note_limit("zeek_window_marks", f"Zeek window publication deduplication is incomplete: {error}")
            result.notes.append("Publication state could not be retained; the stable group identity is preserved.")
        return result

    def finalize(self):
        try:
            for match in self._finalize():
                self.rows.flush()
                yield match
        finally:
            self.rows.flush()

    def _finalize(self):
        if not self.rows.ready:
            return
        try:
            self.rows.clear_derived()
        except StateExhausted as error:
            self.note_limit("zeek_window_derived", f"Zeek window replay could not rebuild derived state: {error}")
            return
        # The ordered index streams all history; neither replay nor expiry drops
        # accepted facts or builds a hunt-wide list of keys, members or matches.
        cursor = self.rows.store().db.execute("SELECT k,id,ts,member,role,weight,payload FROM history ORDER BY k,ts,id")
        previous = None
        for key, identity, stamp, member, role, weight, payload in cursor:
            if previous is not None and key != previous:
                match = self._emit_episode(previous, force=True)
                if match is not None:
                    yield match
            event = self.rows.event(key, identity, stamp, role, payload)
            yield from self._accepted_forward(key, event, member, role, weight)
            previous = key
        if previous is not None:
            match = self._emit_episode(previous, force=True)
            if match is not None:
                yield match

    def retained_events(self):
        return []

    def release_state(self):
        self.rows.close()
        super().release_state()
