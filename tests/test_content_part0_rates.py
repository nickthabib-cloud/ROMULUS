"""Qualifying windows retain early successes without per-event publication churn."""
from dataclasses import replace

import pytest

from romulus.detect.bounded import StateExhausted
from romulus.detect.zeek_rates import NtlmPasswordSpray, ZerologonRate
from tests.fixtures import zeek_logs as zl
from tests.test_ntlm_spray_r3 import assert_named_hit, failures, ntlm, persisted_spray
from tests.test_zeek_rate_monotonic_r3 import ReplayFull
from tests.test_zeek_rate_state import event, toy
from tests.test_zeek_windows_protocols import normalize


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('hit_offset', [3, 7])
def test_pre_crossing_named_hit_is_cited_in_either_arrival_order(shape, reverse, hit_offset):
    rows = [*failures('early', omit_hit=True), ntlm('early-hit', hit_offset, 'victim15', success=True)]
    candidate, events = persisted_spray(rows, shape, reverse)
    assert_named_hit(candidate, events)
    assert candidate['gate_results']['aggregate_summary']['peak'] == 40
    assert candidate['gate_results']['aggregate_summary']['last'] >= max(e.ts.timestamp() for e in events)


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_second_round_pre_crossing_hit_uses_that_rounds_attempt_start(shape):
    rows = [*failures('old'), *failures('new', 700, omit_hit=True),
            ntlm('second-early-hit', 707, 'victim15', success=True)]
    candidate, events = persisted_spray(rows, shape, False)
    assert_named_hit(candidate, events)
    assert candidate['gate_results']['aggregate_summary']['episodes'] == 2


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
@pytest.mark.parametrize('offset', [-1, 0])
def test_success_not_strictly_after_the_first_attempt_does_not_strengthen(shape, offset):
    rows = [*failures('same'), ntlm('not-later-hit', offset, 'victim15', success=True)]
    candidate, _events = persisted_spray(rows, shape, False)
    assert candidate['lane'] == 'lead'


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_pre_crossing_hit_with_same_account_success_before_attempts_is_shared_source(shape):
    rows = [ntlm('prior', -20, 'victim15', success=True), *failures('shared', omit_hit=True),
            ntlm('shared-hit', 3, 'victim15', success=True)]
    candidate, events = persisted_spray(rows, shape, False)
    assert candidate['lane'] == 'lead'
    notes = '\n'.join(candidate['gate_results']['_notes']).lower()
    assert 'shared' in notes and 'victim15' in notes
    assert {e.id for e in events if e.get('ntlm.success') is True} <= set(candidate['event_ids'])


@pytest.mark.parametrize('shape', tuple(zl.WRITERS))
def test_one_batch_spray_emits_first_crossing_then_final_peak(shape):
    rows = [ntlm(f'big-{n}', n/10, f'user{n}', success=False) for n in range(300)]
    owner = NtlmPasswordSpray()
    try:
        stream = owner.consume([normalize(zl.WRITERS[shape](row, f'row{n}')) for n, row in enumerate(rows)])
        initial = next(stream)
        assert initial.aggregate_summary['peak'] == 10 and owner.evaluated == 10
        [final] = list(stream)
        assert final.aggregate_summary['peak'] == 300
        assert 'Peak increased from 10 to 300' in final.revision_reason
    finally:
        owner.release_state()


def test_one_batch_zerologon_does_not_publish_for_each_peak_increment():
    from tests.test_zeek_rate_rules import rows_for

    owner = ZerologonRate()
    try:
        rows = [replace(row, ts=zl.T0+n/1000) for n, row in enumerate(
            rows_for('ZerologonRate', 2000, distinct=True))]
        matches = list(owner.consume([normalize(zl.malcolm(row, f'row{n}')) for n, row in enumerate(rows)]))
        assert len(matches) == 2
        assert matches[0].aggregate_summary['peak'] == 50
        assert matches[-1].aggregate_summary['peak'] == 2000
        assert 'Peak increased from 50 to 2000' in matches[-1].revision_reason
    finally:
        owner.release_state()


def test_pending_peak_is_emitted_after_later_history_refusal(monkeypatch):
    owner = toy()
    original = owner.rows.put
    def refused(key, row, member, role):
        if int(row.id) >= 150:
            raise StateExhausted('synthetic later history refusal')
        return original(key, row, member, role)
    monkeypatch.setattr(owner.rows, 'put', refused)
    try:
        matches = list(owner.consume([event(str(n), n/100) for n in range(300)]))
        assert len(matches) == 2
        assert matches[-1].aggregate_summary['peak'] == 150
        assert owner.limit_reasons()
    finally:
        owner.release_state()


def test_refused_late_replay_still_publishes_a_previously_unpublished_positive():
    owner = toy()
    try:
        assert not list(owner.consume([event('future', 20)]))
        assert not list(owner.consume([event(f'late{n}', n) for n in range(5)]))
        spill = owner.rows.store()
        spill._budget_limited = True
        spill.db = ReplayFull(spill.db, 4)
        matches = list(owner.finalize())
        assert matches and matches[-1].aggregate_summary['peak'] >= 3
        assert any('partial' in note.lower() for note in matches[-1].notes)
        assert owner.limit_reasons()
    finally:
        owner.release_state()
