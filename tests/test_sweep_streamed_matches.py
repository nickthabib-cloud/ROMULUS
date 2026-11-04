"""Native streamed matches retain their input context and report mid-stream refusal."""
import pytest

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.bounded import StateExhausted
from tests.test_windows_process_w4 import native, process, sweep_run


class _StreamProbe(Playbook):
    id = 'test.native_stream'
    families = ('process_exec',)
    os_families = ('windows',)
    kind = 'aggregate'
    assures_negative = False

    def __init__(self, precount):
        super().__init__()
        self.precount = precount

    def consume(self, events):
        assert self._events_pre_scoped
        eligible = self.applicable(events) if self.precount else (
            checked for event in events for checked in self.applicable([event]))
        for event in eligible:
            raw = self.raw_of(event)
            assert raw
            yield Match(self.id, 'A native process creation was recorded', 'observed_action', [event],
                        [pf(event, 'process.executable')], event.ts, 'medium', 'lead', 'medium',
                        raw_copies=raw)
            raise StateExhausted('test physical refusal after a published native match')


@pytest.mark.parametrize('precount,refused', [(True, 0), (False, 2)])
def test_streamed_consume_keeps_raw_and_scope_and_partial_positive(tmp_path, monkeypatch, precount, refused):
    records = [native(process(r'C:\Windows\System32\cmd.exe', r'EXAMPLE\alice', n + 1),
                      n + 1, offset=n) for n in range(3)]
    probe = _StreamProbe(precount)
    findings, _ = sweep_run(tmp_path, monkeypatch, probe, [records], assert_raw=[records[0]])
    assert len(findings) == 1 and findings[0]['lane'] == 'lead'
    assert not probe._events_pre_scoped
    assert probe.os_applicable == 3
    assert probe.capped == refused and 'state_disk' in probe.limits
