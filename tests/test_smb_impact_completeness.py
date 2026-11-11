"""Group-scoped loss accounting for retained SMB impact evidence."""
from __future__ import annotations

import json
import sqlite3

import pytest

from romulus.detect.bounded import StateExhausted
from romulus.detect.smb_impact import _ImpactRows
from romulus.evidence.typed import RawRef
from tests.test_smb_impact import rule as impact_rule
from tests.test_smb_impact import smb

rule = impact_rule


def refuse(rule, rows):
    rule.budget.force_full('synthetic member refusal', lambda account: account.name.startswith(rule.id))
    rule.consume(rows)
    rule.budget.forced.clear()
    rule.budget._recalm()


@pytest.mark.parametrize('before', [False, True])
@pytest.mark.parametrize('same_group', [False, True])
def test_member_refusal_is_group_scoped_and_retained_high_survives(rule, before, same_group):
    lost = smb('lost', 5000, client='10.0.0.1' if same_group else '10.9.9.9')
    # Establish the schema before injecting a capacity refusal.
    rule.rows.store()
    if before:
        refuse(rule, [lost])
    rule.consume(smb(i, i / 5) for i in range(150))
    if not before:
        refuse(rule, [lost])
    [match] = list(rule.finalize())
    assert match.proposed_lane == 'high'
    if same_group:
        assert 'at least 150 retained' in match.claim.lower()
        assert 'ratio is unresolved' in match.claim.lower()
        assert any('partial' in note.lower() for note in match.notes)
    else:
        assert '100.0%' in match.claim
        assert 'ratio is unresolved' not in match.claim


def test_raw_reference_chunk_refusal_does_not_lose_accepted_member(rule, monkeypatch):
    rule.consume(smb(i) for i in range(149))
    row = smb('last')
    row.raw += [RawRef(target='extra', native_id=f'extra-{i}') for i in range(128)]
    original = rule.rows._put
    calls = 0

    def fail_second(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise StateExhausted('synthetic reference chunk refusal')
        return original(*args)

    monkeypatch.setattr(rule.rows, '_put', fail_second)
    rule.consume([row])
    [match] = list(rule.finalize())
    assert match.proposed_lane == 'high' and '100.0%' in match.claim
    assert rule.capped and any('reference retention' in note for note in rule.limit_reasons())


def test_recovery_read_failure_cannot_restore_false_complete_ratio(rule, monkeypatch):
    rule.consume(smb(i) for i in range(150))
    original_store = rule.rows.store
    failing = False

    def fail_put(*args):
        nonlocal failing
        failing = True
        raise StateExhausted('synthetic recovery failure')

    def fail_read():
        if failing:
            raise StateExhausted('synthetic canonical read failure')
        return original_store()

    monkeypatch.setattr(rule.rows, '_put', fail_put)
    monkeypatch.setattr(rule.rows, 'store', fail_read)
    rule.consume([smb('lost')])
    failing = False
    [match] = list(rule.finalize())
    assert match.proposed_lane == 'high' and 'ratio is unresolved' in match.claim
    assert any('canonical member' in note for note in rule.limit_reasons())


def test_refusal_storm_is_disk_backed_and_budgeted(rule):
    rule.rows.store()
    refuse(rule, (smb(f'lost-{i}', share=f'share-{i}') for i in range(10_000)))
    db = rule.rows.store().db
    assert db.execute('SELECT COUNT(*) FROM impact_refused').fetchone()[0] == 10_000
    assert rule.budget.physical_used <= rule.budget.disk_total
    assert len(rule.rows.pending) <= 256
    assert not any(isinstance(v, (set, dict)) and len(v) >= 10_000 for v in vars(rule.rows).values())


def test_refused_key_table_failure_is_honest_and_keeps_positive(rule, monkeypatch):
    rule.consume(smb(i) for i in range(150))
    original = rule.rows.write

    def fail_refused(kind, operation, **kwargs):
        if kind == 'refused':
            raise StateExhausted('synthetic refusal table full')
        return original(kind, operation, **kwargs)

    monkeypatch.setattr(rule.rows, 'write', fail_refused)
    refuse(rule, [smb('lost', client='10.9.9.9')])
    [match] = list(rule.finalize())
    assert match.proposed_lane == 'high' and 'ratio is unresolved' in match.claim
    assert any('refused-key' in note for note in rule.limit_reasons())


def test_reopening_retained_database_cannot_forget_refusal(rule):
    rule.consume(smb(i) for i in range(150))
    refuse(rule, [smb('lost')])
    spill = rule.spill()
    spill.db.close()
    spill.db = sqlite3.connect(spill.path)
    rule.rows = _ImpactRows(rule)
    [match] = list(rule.finalize())
    assert match.proposed_lane == 'high' and 'ratio is unresolved' in match.claim


def test_incomplete_group_without_retained_arm_is_only_a_limit(rule):
    rule.consume(smb(i) for i in range(99))
    refuse(rule, [smb('lost')])
    assert not list(rule.finalize())
    assert rule.capped and rule.limit_reasons()


def test_refusal_before_schema_is_honest_when_later_members_are_retained(rule):
    refuse(rule, [smb('lost')])
    rule.consume(smb(i) for i in range(150))
    [match] = list(rule.finalize())
    assert match.proposed_lane == 'high' and 'ratio is unresolved' in match.claim


def test_conflict_after_finalize_revises_ratio_to_lower_bound(rule):
    rule.consume(smb(i) for i in range(150))
    [first] = list(rule.finalize())
    assert '100.0%' in first.claim
    rule.consume([smb(0, name='different.other')])
    [revised] = list(rule.finalize())
    assert revised.proposed_lane == 'high' and 'ratio is unresolved' in revised.claim


def test_late_refused_member_cannot_invalidate_retained_lower_bound(rule):
    rule.consume(smb(i, 200) for i in range(150))
    refuse(rule, [smb('late', 0, name='old.other')])
    [match] = list(rule.finalize())
    assert match.proposed_lane == 'high' and 'at least 150 retained' in match.claim


@pytest.mark.parametrize('stage', ['add', 'expire'])
def test_replay_refusal_keeps_completed_positive_and_other_groups(rule, monkeypatch, stage):
    rule.consume([*(smb(i, i / 5) for i in range(150)), smb('later', 1000),
                  *(smb(f'b{i}', i / 5, client='10.9.9.9') for i in range(150))])
    original = getattr(rule.rows, stage)
    failed = False

    def fail_once(*args):
        nonlocal failed
        trigger = args[0] == 'later' if stage == 'add' else args[0] > 1767225900
        if trigger and not failed:
            failed = True
            raise StateExhausted('synthetic replay refusal')
        return original(*args)

    monkeypatch.setattr(rule.rows, stage, fail_once)
    matches = list(rule.finalize())
    assert len(matches) == 2 and all(m.proposed_lane == 'high' for m in matches)
    assert rule.limit_reasons()


def test_canonical_conflict_marks_only_its_group(rule):
    rule.consume([*(smb(i) for i in range(150)),
                  *(smb(f'b{i}', client='10.9.9.9') for i in range(150))])
    rule.consume([smb(0, name='conflict.other')])
    matches = list(rule.finalize())
    assert len(matches) == 2 and all(m.proposed_lane == 'high' for m in matches)
    assert sum('ratio is unresolved' in m.claim for m in matches) == 1
    assert rule.rows.store().db.execute('SELECT k FROM impact_refused').fetchall() == [
        (json.dumps(('10.0.0.1', '10.0.0.2', 'docs'), separators=(',', ':')),)]
