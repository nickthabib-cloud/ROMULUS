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
from typing import ClassVar

from romulus.detect.base import LANES, Match, Playbook, pf
from romulus.detect.bounded import StateExhausted, register_store
from romulus.evidence.typed import RawRef, TypedEvent
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event

_SAMPLE = 3
_PARTIAL_CITATIONS = (
    "Citation coverage is partial: the sample retains at most three events and three native references per event; "
    "counted attempt references are deduplicated independently of this citation sample."
)


def _bytes(*values):
    return sum(len(value) if isinstance(value, bytes) else len(str(value).encode()) for value in values)


class _WindowRows:
    """Retained history and rebuildable indexed counters share the hunt's spill budget."""

    schema = (
        "CREATE TABLE history(k TEXT,id TEXT,ts REAL,member TEXT,role TEXT,weight INTEGER,payload BLOB,PRIMARY KEY(k,id))",
        "CREATE INDEX history_time ON history(k,ts,id)",
        "CREATE TABLE raw_refs(k TEXT,ref TEXT,id TEXT,target TEXT,native_id TEXT,digest TEXT,priority INTEGER,PRIMARY KEY(k,ref))",
        "CREATE INDEX raw_refs_event ON raw_refs(k,id,priority,ref)",
        "CREATE TABLE live(k TEXT PRIMARY KEY,watermark REAL,total INTEGER,distinct_n INTEGER)",
        "CREATE TABLE active(k TEXT,id TEXT,ts REAL,member TEXT,weight INTEGER,PRIMARY KEY(k,id))",
        "CREATE INDEX active_time ON active(k,ts,id)",
        "CREATE TABLE members(k TEXT,member TEXT,n INTEGER,PRIMARY KEY(k,member))",
        "CREATE TABLE marks(k TEXT PRIMARY KEY,lane INTEGER)",
    )

    def __init__(self, owner):
        self.owner, self.ready, self.account = owner, False, None
        self.derived_bytes = 0
        register_store(owner, self)

    def room(self, kind):
        reason = self.owner.state_budget().new_key_reason(self.account)
        if reason:
            self.owner.note_limit("zeek_window_" + kind, f"Zeek window {kind} growth is incomplete: {reason}")
        return not reason

    def store(self):
        spill = self.owner.spill()
        if self.ready:
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

    def write(self, kind, operation, *, growing=True):
        spill = self.store()
        if growing and not self.room(kind):
            raise StateExhausted(f"the Zeek window {kind} state could not grow")
        if self.owner.state_budget().hard:
            raise StateExhausted(self.owner.state_budget().hard)
        # Like Spill.write, reclaim expendable citations before setting the
        # physical page ceiling; all statements below roll back together.
        self.owner.state_budget().reclaim_citations(4 * spill._page)
        spill.cap()
        try:
            spill.db.execute("SAVEPOINT zeek_window_write")
            result, delta = operation(spill.db)
            spill.db.execute("RELEASE zeek_window_write")
        except sqlite3.OperationalError as error:
            spill.db.rollback()
            raise spill.failed(error, account=self.account) from error
        except BaseException:
            spill.db.rollback()
            raise
        finally:
            spill.grew()
        self.owner.state_budget().charge(self.account, delta)
        if kind == "derived":
            self.derived_bytes += delta
        return result

    def put(self, key, event, member, role):
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
            canonical = expand_event(previous[4]) if previous else self.owner.compact(event)
            if previous is None:
                payload = compact_event(canonical)
                db.execute("INSERT INTO history VALUES(?,?,?,?,?,?,?)",
                           (key, event.id, event.ts.timestamp(), member, role, 0, payload))
                delta += _bytes(key, event.id, member, role, payload) + 128
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
            packed = compact_event(canonical)
            delta += len(packed) - len(payload)
            db.execute("UPDATE history SET weight=?,payload=? WHERE k=? AND id=?", (weight, packed, key, event.id))
            if db.execute("INSERT OR IGNORE INTO marks VALUES(?,?)", (key, len(LANES))).rowcount:
                delta += _bytes(key) + 96
            return (canonical, weight), delta

        return self.write("history", insert)

    def advance(self, key, event, member, role, weight):
        db = self.store().db
        previous = db.execute("SELECT watermark,total,distinct_n FROM live WHERE k=?", (key,)).fetchone()
        stamp = event.ts.timestamp()
        if previous and stamp < previous[0]:
            return None

        def update(db):
            total, distinct = previous[1:] if previous else (0, 0)
            delta = 0 if previous else _bytes(key) + 128
            if previous is None:
                db.execute("INSERT INTO live VALUES(?,?,0,0)", (key, stamp))
            while True:
                expired = db.execute("SELECT id,member,weight FROM active WHERE k=? AND ts<? ORDER BY ts,id LIMIT 1",
                                     (key, stamp - self.owner.seconds)).fetchone()
                if expired is None:
                    break
                identity, old_member, old_weight = expired
                total -= old_weight
                db.execute("DELETE FROM active WHERE k=? AND id=?", (key, identity))
                delta -= _bytes(key, identity, old_member) + 128
                count = db.execute("SELECT n FROM members WHERE k=? AND member=?", (key, old_member)).fetchone()[0]
                if count == 1:
                    db.execute("DELETE FROM members WHERE k=? AND member=?", (key, old_member))
                    distinct -= 1
                    delta -= _bytes(key, old_member) + 96
                else:
                    db.execute("UPDATE members SET n=n-1 WHERE k=? AND member=?", (key, old_member))
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
            return (total, distinct), delta

        return self.write("derived", update)

    def clear_derived(self):
        def clear(db):
            for name in ("active", "members", "live"):
                db.execute("DELETE FROM " + name)
            return None, -self.derived_bytes
        self.write("derived", clear, growing=False)

    def close(self):
        if self.account:
            self.owner.state_budget().charge(self.account, -self.account.used)
        self.owner.close_spill()
        self.account, self.ready, self.derived_bytes = None, False, 0


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

    def consume(self, events):
        for event in events:
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
            yield from self._forward(key, canonical, member, role, weight)

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
                    match = self._publish(key, event, *decision)
                    if match is not None:
                        match.notes.append("Counts are lower bounds supported by this event's accepted references; other retained window context was not counted because derived state was unavailable.")
                        yield match
            return
        if counts is None:
            return
        total, distinct = counts
        if (distinct if self.distinct else total) < self.threshold:
            return
        if role == "success":
            latest = self.rows.store().db.execute("SELECT ts FROM active WHERE k=? ORDER BY ts DESC,id DESC LIMIT 1",
                                                  (key,)).fetchone()
            # Equal timestamps do not establish that success followed attempts.
            if latest is None or latest[0] >= event.ts.timestamp():
                return
        decision = self.describe(event, total, distinct, role)
        if decision is not None:
            match = self._publish(key, event, *decision)
            if match is not None:
                yield match

    def _publish(self, key, event, lane, claim, notes):
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
        if not self.rows.ready:
            return
        try:
            self.rows.clear_derived()
        except StateExhausted as error:
            self.note_limit("zeek_window_derived", f"Zeek window replay could not rebuild derived state: {error}")
            return
        # The ordered index streams all history; neither replay nor expiry drops
        # accepted facts or builds a hunt-wide list of keys, members or matches.
        cursor = self.rows.store().db.execute("SELECT k,member,role,weight,payload FROM history ORDER BY k,ts,id")
        for key, member, role, weight, payload in cursor:
            yield from self._forward(key, expand_event(payload), member, role, weight)

    def retained_events(self):
        return []

    def release_state(self):
        self.rows.close()
        super().release_state()
