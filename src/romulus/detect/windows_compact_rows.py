"""Indexed correlation facts without duplicating unneeded native source bodies."""
from __future__ import annotations

from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_rows import WindowsRows
from romulus.hunt.citations import COMPACT_CITATION_NOTE, compact_event, expand_event


class CompactWindowsRows(WindowsRows):
    """Use the existing physical/accounted store and publication citation protocol."""

    def compact_fields(self, key):
        return None

    def put(self, key, event, value=''):
        fields = self.compact_fields(key)
        if fields is None:
            return super().put(key, event, value)
        compact = event.model_copy(update={
            'fields': {name: fact for name, fact in event.fields.items() if name in fields},
            'caveats': list(dict.fromkeys([*event.caveats, COMPACT_CITATION_NOTE]))})
        return self._insert(key, event, value, compact_event(compact), '')

    def fingerprint(self, key, event, value):
        """A nonqualifying creation needs identity/time/conflict detection, no event body."""
        return self._insert(key, event, value, '', '')

    def _insert(self, key, event, value, payload, raw):
        spill = self.store()
        if spill.execute('SELECT 1 FROM windows_rows WHERE k=? AND id=?', (key, event.id)).fetchone():
            return False
        if not self.room():
            self.owner.refuse('windows_row_refused', 'The disk budget refused a correlation record')
            return False
        try:
            spill.write('INSERT INTO windows_rows VALUES(?,?,?,?,?,?)',
                        [(key, event.id, event.ts.timestamp(), value, payload, raw)])
        except StateExhausted as exc:
            self.owner.refuse('windows_row_refused', f'A compact correlation row could not be written: {exc}')
            return False
        size = sum(len(item if isinstance(item, bytes) else item.encode()) for item in (key, value, payload, raw)) + 256
        self.owner.state_budget().charge(self.account, size)
        return True

    @staticmethod
    def hydrate(row):
        if isinstance(row[0], bytes):
            return expand_event(row[0]), {}
        return WindowsRows.hydrate(row)

    def iterate(self, key=None, *, prefix=None):
        if not self.ready:
            return
        if prefix is not None:
            clause, args = ' WHERE k>=? AND k<?', (prefix, prefix + '\uffff')
        elif key is not None:
            clause, args = ' WHERE k=?', (key,)
        else:
            clause, args = '', ()
        for k, payload, raw, value in self.store().execute(
                'SELECT k,event,raw,value FROM windows_rows' + clause + ' ORDER BY k,ts,id', args):
            if payload:
                event, copies = self.hydrate((payload, raw))
                yield k, event, copies, value


FENCE_FIELDS = frozenset({'event.code', 'event.channel', 'event.provider', 'host.full_name',
                         'process.guid', 'process.fence', 'system.event'})
