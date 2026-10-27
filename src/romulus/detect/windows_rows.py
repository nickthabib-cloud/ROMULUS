"""Budgeted, indexed Windows correlation rows and raw citation bodies."""
from __future__ import annotations

import json

from romulus.detect.bounded import StateExhausted, register_store
from romulus.evidence.typed import TypedEvent


def row_key(*parts):
    return json.dumps(parts, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


class WindowsRows:
    """Never discard old rows for a memory or time bound; only a stated disk refusal can stop growth."""

    def __init__(self, owner):
        self.owner, self.ready, self.account = owner, False, None
        register_store(owner, self)

    def store(self):
        spill = self.owner.spill()
        if not self.ready:
            spill.db.execute("CREATE TABLE windows_rows(k TEXT,id TEXT,ts REAL,value TEXT,event TEXT,raw TEXT,PRIMARY KEY(k,id))")
            spill.db.execute("CREATE INDEX windows_rows_time ON windows_rows(k,ts,id)")
            spill.db.execute("CREATE INDEX windows_rows_value ON windows_rows(k,value,ts)")
            spill.db.execute("CREATE TABLE windows_marks(k TEXT PRIMARY KEY,value TEXT)")
            self.account = self.owner.state_budget().account(f"{self.owner.id}:windows_rows", strong=True)
            self.ready = True
        return spill

    def room(self):
        reason = self.owner.state_budget().new_key_reason(self.account)
        if reason:
            self.owner.note_limit("windows_rows", "Correlation row growth is incomplete: " + reason)
        return not reason

    def put(self, key, event, value=""):
        spill = self.store()
        if spill.execute("SELECT 1 FROM windows_rows WHERE k=? AND id=?", (key, event.id)).fetchone():
            return False
        if not self.room():
            self.owner.refuse("windows_row_refused", "The disk budget refused a correlation record")
            return False
        payload, raw = event.model_dump_json(), json.dumps(self.owner.raw_of(event), ensure_ascii=True)
        try:
            spill.write("INSERT INTO windows_rows VALUES(?,?,?,?,?,?)",
                        [(key, event.id, event.ts.timestamp(), value, payload, raw)])
        except StateExhausted as exc:
            self.owner.refuse("windows_row_refused", f"A correlation row could not be written: {exc}")
            return False
        self.owner.state_budget().charge(self.account, sum(len(item.encode()) for item in (key, value, payload, raw)) + 256)
        return True

    def marked(self, key):
        return bool(self.store().execute("SELECT 1 FROM windows_marks WHERE k=?", (key,)).fetchone())

    def marker(self, key):
        row = self.store().execute("SELECT value FROM windows_marks WHERE k=?", (key,)).fetchone()
        return row[0] if row else None

    def remember(self, key, value):
        previous = self.marker(key)
        delta = (len(key.encode()) + len(value.encode()) + 96 if previous is None
                 else len(value.encode()) - len(previous.encode()))
        if delta > 0 and not self.room():
            return
        try:
            self.store().write("INSERT OR REPLACE INTO windows_marks VALUES(?,?)", [(key, value)])
            self.owner.state_budget().charge(self.account, delta)
        except StateExhausted as exc:
            self.owner.note_limit("windows_marks", f"Correlation revision state could not be retained: {exc}")

    def first(self, key):
        """Failure to retain a dedup marker never suppresses a detection."""
        if self.marked(key):
            return False
        if not self.room():
            return True
        try:
            self.store().write("INSERT OR IGNORE INTO windows_marks VALUES(?,?)", [(key, "")])
            self.owner.state_budget().charge(self.account, len(key.encode()) + 96)
        except StateExhausted as exc:
            self.owner.note_limit("windows_marks", f"Correlation dedup markers could not be retained: {exc}")
        return True

    @staticmethod
    def hydrate(row):
        return TypedEvent.model_validate_json(row[0]), json.loads(row[1])

    def witnesses(self, key, end, seconds, count, *, distinct=False):
        if distinct:
            cursor = self.store().execute(
                "SELECT w.event,w.raw FROM windows_rows w JOIN "
                "(SELECT MIN(id) AS id FROM windows_rows WHERE k=? AND ts>=? AND ts<=? GROUP BY value LIMIT ?) s "
                "ON w.k=? AND w.id=s.id ORDER BY w.ts,w.id", (key, end-seconds, end, count, key))
        else:
            cursor = self.store().execute("SELECT event,raw FROM windows_rows WHERE k=? AND ts>=? AND ts<=? "
                                          "ORDER BY ts,id LIMIT ?", (key, end-seconds, end, count))
        return [self.hydrate(row) for row in cursor]

    def iterate(self, key=None):
        if not self.ready:
            return
        clause, args = (" WHERE k=?", (key,)) if key is not None else ("", ())
        for k, payload, raw, value in self.store().execute("SELECT k,event,raw,value FROM windows_rows" + clause + " ORDER BY k,ts,id", args):
            yield k, TypedEvent.model_validate_json(payload), json.loads(raw), value

    def prior(self, key, end, seconds):
        row = self.store().execute("SELECT event,raw FROM windows_rows WHERE k=? AND ts<=? AND ts>=? "
                                   "ORDER BY ts DESC,id LIMIT 1", (key, end, end-seconds)).fetchone()
        return self.hydrate(row) if row else None

    def close(self):
        if self.account:
            self.owner.state_budget().charge(self.account, -self.account.used)
        self.owner.close_spill()
        self.ready, self.account = False, None
