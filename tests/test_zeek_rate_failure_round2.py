"""Optional summaries and commit faults cannot erase already accepted positives."""
import sqlite3

import pytest

from romulus.detect.bounded import StateExhausted
from romulus.detect.zeek_rates import NtlmPasswordSpray, ZerologonRate
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_rate_rules import rows_for
from tests.test_zeek_rate_state import event, toy
from tests.test_zeek_windows_protocols import normalize


@pytest.mark.parametrize('shape',tuple(zl.WRITERS))
def test_zerologon_high_survives_optional_episode_summary_refusal(shape,monkeypatch):
    rule=ZerologonRate()
    original=rule.rows.write
    def write(kind,operation,**kwargs):
        if kind=='derived' and operation.__name__=='save':
            raise StateExhausted('injected optional episode summary full')
        return original(kind,operation,**kwargs)
    monkeypatch.setattr(rule.rows,'write',write)
    events=[normalize(zl.WRITERS[shape](row,f'full-{n}')) for n,row in enumerate(rows_for('ZerologonRate',50))]
    try:
        matches=list(rule.consume(events))
        assert any(match.proposed_lane=='high' for match in matches)
        assert any('episode' in reason.casefold() for reason in rule.limit_reasons())
        assert any('summary' in note for match in matches for note in match.notes)
        assert rule.rows.store().db.execute('SELECT COUNT(*) FROM history').fetchone()[0]==50
    finally:
        rule.release_state()


class CommitFault:
    def __init__(self,connection,failures):
        self.connection,self.failures=connection,failures

    def __getattr__(self,name):
        return getattr(self.connection,name)

    def commit(self):
        if self.failures:
            self.failures-=1
            self.connection.rollback()
            raise sqlite3.OperationalError('injected commit-time database or disk is full')
        return self.connection.commit()


def test_commit_time_full_restores_accepted_rows_before_publishing():
    rule=toy()
    try:
        spill=rule.rows.store()
        spill.db=CommitFault(spill.db,1)
        matches=list(rule.consume([event('a'),event('b',1),event('c',2)]))
        assert matches and '3 attempt references' in matches[-1].claim
        assert spill.db.execute('SELECT COUNT(*) FROM history').fetchone()[0]==3
        assert not spill.db.in_transaction and not rule.rows.pending
        assert any('commit' in reason.casefold() for reason in rule.limit_reasons())
    finally:
        rule.release_state()


def test_failed_commit_recovery_keeps_the_unrestored_bounded_journal_for_retry():
    rule=toy(threshold=1000)
    try:
        spill=rule.rows.store()
        spill.db=CommitFault(spill.db,2)
        with pytest.raises(StateExhausted):
            list(rule.consume([event('accepted')]))
        assert rule.rows.pending
        assert rule.limit_reasons()
        rule.rows.flush()
        assert spill.db.execute('SELECT COUNT(*) FROM history').fetchone()[0]==1
        assert not rule.rows.pending
    finally:
        rule.release_state()


def test_natural_consume_retry_restores_journal_before_reading_canonical_history():
    rule=toy(threshold=1000)
    try:
        spill=rule.rows.store()
        spill._budget_limited=True
        spill.db=CommitFault(spill.db,2)
        with pytest.raises(StateExhausted):
            list(rule.consume([event('accepted')]))
        assert rule.rows.recovering and rule.rows.pending
        rule.state_budget()._capacity_generation+=1
        assert not list(rule.consume([event('accepted',refs=['accepted','another-real-copy'])]))
        assert spill.db.execute('SELECT COUNT(*),SUM(weight) FROM history').fetchone()==(1,2)
        assert spill.db.execute('SELECT COUNT(*) FROM raw_refs').fetchone()[0]==2
        assert not rule.rows.pending and not rule.rows.recovering
    finally:
        rule.release_state()


@pytest.mark.parametrize('shape',tuple(zl.WRITERS))
def test_partial_summary_cannot_overwrite_high_fallback_with_a_stale_lead_witness(shape,monkeypatch):
    rule=NtlmPasswordSpray()
    events=[normalize(zl.WRITERS[shape](row,f'stale-{n}'))
            for n,row in enumerate(rows_for('NtlmPasswordSpray',10,success=True))]
    try:
        assert list(rule.consume(events[:-1]))[-1].proposed_lane=='lead'
        original=rule.rows.write
        def write(kind,operation,**kwargs):
            if kind=='derived' and operation.__name__=='save':
                raise StateExhausted('injected optional summary full after lead')
            return original(kind,operation,**kwargs)
        monkeypatch.setattr(rule.rows,'write',write)
        matches=list(rule.consume(events[-1:]))
        assert matches and matches[-1].proposed_lane=='high'
        assert any(row.get('ntlm.success') is True for row in matches[-1].events)
        assert any('summary' in note for note in matches[-1].notes)
    finally:
        rule.release_state()
