"""Immediate PPID corrections and monotonic SMB episode summaries."""
from itertools import permutations

import pytest

from romulus.detect.bounded import StateExhausted
from romulus.detect.windows_sequence_extensions import ParentProcessSpoofing, SmbHostDiscovery
from tests.test_windows_sequence_round2 import access, creation
from tests.windows_event_support import event
from tests.windows_process_support import stored


@pytest.mark.parametrize('reverse', [False, True])
def test_unknown_long_lived_parent_spoofing_is_high_before_finalize(reverse):
    records = [access(), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in records if e.id in ids]
    try:
        first, second = reversed(records) if reverse else records
        assert list(owner.consume([first])) == []
        [match] = list(owner.consume([second]))
        assert match.proposed_lane == 'high'
        assert any('target creation record' in note for note in match.notes)
        assert not list(owner.finalize())
    finally:
        owner.release_state()


def test_late_creator_proof_corrects_same_fold_without_hiding_remaining_highs():
    records = [access(target='target-a', native='a'),
        creation('child-a', 'target-a', r'C:\Tools\first.exe', offset=2),
        access(source='second-actor', target='target-b', native='b'),
        creation('child-b', 'target-b', r'C:\Tools\last.exe', offset=3)]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in records if e.id in ids]
    try:
        matches = list(owner.consume(records))
        assert matches and matches[-1].proposed_lane == 'high'
        identity = matches[-1].group_key
        [remaining] = list(owner.consume([creation('target-a', 'actor', r'C:\Windows\explorer.exe')]))
        assert remaining.group_key == identity and remaining.proposed_lane == 'high'
        [corrected] = list(owner.consume([creation('target-b', 'second-actor', r'C:\Windows\explorer.exe')]))
        assert corrected.group_key == identity and corrected.proposed_lane == 'lead'
        assert 'creator' in corrected.revision_reason.lower()
    finally:
        owner.release_state()


@pytest.mark.parametrize('parents', [('other', 'actor'), ('actor', 'other')])
@pytest.mark.parametrize('together', [False, True])
def test_conflicting_target_creations_restore_uncertain_ppid_membership(parents, together):
    records = [access(), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    targets = [creation('parent', parent, r'C:\Windows\explorer.exe').model_copy(
        update={'id': 'target-' + parent}) for parent in parents]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in [*records, *targets] if e.id in ids]
    try:
        [original] = list(owner.consume(records))
        revisions = [original]
        for partition in ([targets] if together else [[row] for row in targets]):
            revisions.extend(owner.consume(partition))
        final = revisions[-1]
        assert final.group_key == original.group_key and final.proposed_lane == 'high'
        assert final.claim.endswith('1 matching child sequence(s) on ws01.')
        assert any('Conflicting recorded target parents' in reason for reason in owner.limit_reasons())
        assert any('conflicting' in note.lower() for note in final.notes)
        assert {'target-other', 'target-actor'} <= {e.id for e in final.events}
        assert list(owner.consume(targets)) == []
        assert owner.rows.store().execute('SELECT SUM(high),SUM(valid) FROM ppid_members').fetchone() == (1, 1)
        if together:
            assert all(match.proposed_lane == 'high' for match in revisions)
    finally:
        owner.release_state()


def test_ppid_conflict_already_known_is_cited_as_ambiguity_not_missing_context():
    targets = [creation('parent', parent, r'C:\Windows\explorer.exe').model_copy(
        update={'id': 'target-' + parent}) for parent in ('actor', 'other')]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in targets if e.id in ids]
    try:
        assert list(owner.consume(targets)) == []
        [match] = list(owner.consume([access(), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]))
        assert match.proposed_lane == 'high'
        assert any('Conflicting recorded target parents' in note for note in match.notes)
        assert not any('outside the retained context' in note for note in match.notes)
        assert {'target-other', 'target-actor'} <= {e.id for e in match.events}
    finally:
        owner.release_state()


@pytest.mark.parametrize('order', list(permutations(range(4))))
def test_ppid_conflicting_target_records_preserve_pair_in_every_batch_order(order):
    targets = [creation('parent', parent, r'C:\Windows\explorer.exe').model_copy(
        update={'id': 'target-' + parent}) for parent in ('actor', 'other')]
    records = [access(), *targets, creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in records if e.id in ids]
    try:
        matches = list(owner.consume([records[n] for n in order]))
        assert matches and all(match.proposed_lane == 'high' for match in matches)
        assert {'access', 'create-child', 'target-actor', 'target-other'} <= {e.id for e in matches[-1].events}
        assert not list(owner.finalize())
    finally:
        owner.release_state()


def test_ordinary_ppid_fold_preserves_original_claim():
    owner = ParentProcessSpoofing()
    try:
        [match] = list(owner.consume([access(), creation('child', 'parent', r'C:\Tools\child.exe', offset=2)]))
        assert match.claim.endswith('1 matching child sequence(s) on ws01.')
    finally:
        owner.release_state()


def test_ppid_fold_cites_first_and_latest_real_sequences():
    records = [access(), *[creation(f'child-{n}', 'parent', f'C:\\Tools\\child-{n}.exe', offset=2+n) for n in range(3)]]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in records if e.id in ids]
    try:
        [match] = stored(list(owner.consume(records)))
        assert {'create-child-0', 'create-child-2', 'access'} <= {e.id for e in match.events}
        assert len(match.events) <= 6
    finally:
        owner.release_state()


def test_ppid_first_latest_bounds_follow_event_time_for_reverse_arriving_children():
    rows = [access(), *[creation(f'child-{n}', 'parent', f'C:\\Tools\\child-{n}.exe', offset=2+n) for n in range(3)]]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in rows if e.id in ids]
    try:
        list(owner.consume([rows[0]]))
        matches = [match for child in reversed(rows[1:]) for match in owner.consume([child])]
        match = matches[-1]
        assert match.ts == rows[-1].ts
        assert {'create-child-0', 'create-child-2'} <= {e.id for e in match.events}
    finally:
        owner.release_state()


def smb_burst(prefix, count, start):
    return [event('net_socket', 3, native=f'{prefix}-{n}', offset=start+n, **{
        'source.ip': '10.0.0.1', 'destination.ip': f'10.{1+n//65000}.{(n//250)%250}.{n%250+1}',
        'destination.port': 445, 'network.direction': 'egress', 'network.transport': 'tcp'}) for n in range(count)]


def test_smb_two_episodes_revise_one_identity_with_the_larger_peak_and_real_citations():
    first, second = smb_burst('first', 25, 0), smb_burst('second', 300, 3600)
    owner = SmbHostDiscovery()
    try:
        initial = list(owner.consume(first))
        assert initial and initial[-1].aggregate_summary['peak'] == 25
        revised = list(owner.consume(second))
        assert revised and revised[-1].group_key == initial[-1].group_key
        match = revised[-1]
        assert match.aggregate_summary['episodes'] == 2 and match.aggregate_summary['peak'] == 300
        assert {'first-24', 'second-299'} <= {e.id for e in match.events}
        assert len(match.events) <= 6
        assert '2 qualifying episodes' in match.claim and 'peak 300' in match.claim
    finally:
        owner.release_state()


@pytest.mark.parametrize('stop', [5, 30, 70])
def test_smb_refused_replay_never_emits_a_smaller_summary(monkeypatch, stop):
    owner = SmbHostDiscovery()
    try:
        original = [*owner.consume(smb_burst('a', 25, 0)), *owner.consume(smb_burst('b', 40, 3600))]
        assert original and original[-1].aggregate_summary['peak'] == 40
        scan = owner.rows.scan
        def refused():
            for n, row in enumerate(scan()):
                if n == stop:
                    raise StateExhausted('synthetic disk refusal during ordered replay')
                yield row
        monkeypatch.setattr(owner.rows, 'scan', refused)
        assert list(owner.finalize()) == []
        assert owner.limit_reasons()
    finally:
        owner.release_state()


def test_smb_late_burst_replay_recovers_both_episodes_and_keeps_the_larger_peak():
    owner = SmbHostDiscovery()
    try:
        current = list(owner.consume(smb_burst('later', 40, 3600)))
        assert current[-1].aggregate_summary['episodes'] == 1
        assert not list(owner.consume(smb_burst('earlier', 25, 0)))
        [match] = list(owner.finalize())
        assert match.aggregate_summary['episodes'] == 2 and match.aggregate_summary['peak'] == 40
        assert {'earlier-24', 'later-39'} <= {e.id for e in match.events}
    finally:
        owner.release_state()


def test_smb_steady_batches_only_revise_the_final_last_window_and_keep_state_coalesced():
    owner = SmbHostDiscovery()
    try:
        [initial] = list(owner.consume(smb_burst('first', 25, 0)))
        for n in range(200):
            row = smb_burst(f'repeat-{n}', 1, 40+n)[0]
            assert not list(owner.consume([row]))
        [final] = list(owner.finalize())
        assert final.aggregate_summary['episodes'] == initial.aggregate_summary['episodes'] == 1
        assert final.aggregate_summary['peak'] == 25 and 'last qualifying window' in final.revision_reason
        assert owner.rows.store().execute('SELECT COUNT(*) FROM windows_rows').fetchone()[0] == 25
        assert owner.rows.account.used < 100_000
    finally:
        owner.release_state()


def test_middle_genuine_ppid_sequence_remains_high_and_cited_after_endpoint_corrections():
    rows = []
    for n in range(3):
        rows += [access(source=f'actor-{n}', target=f'target-{n}', native=f'access-{n}'),
                 creation(f'child-{n}', f'target-{n}', r'C:\Tools\child.exe', offset=2+n)]
    owner = ParentProcessSpoofing()
    owner.load = lambda ids: [e for e in rows if e.id in ids]
    try:
        list(owner.consume(rows))
        list(owner.consume([creation('target-0', 'actor-0', r'C:\Windows\explorer.exe')]))
        [match] = list(owner.consume([creation('target-2', 'actor-2', r'C:\Windows\explorer.exe')]))
        assert match.proposed_lane == 'high'
        assert {'create-child-0', 'create-child-1', 'create-child-2'} <= {e.id for e in match.events}
        assert len(match.events) <= 7
    finally:
        owner.release_state()


def test_smaller_smb_resume_prefix_cannot_replace_the_persisted_peak_or_citations():
    from romulus.hunt.publish import publish_match
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo

    engine = make_engine(':memory:')
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt('smb-r3', {'targets': []}, 'digest', 'test')
    owner, resumed = SmbHostDiscovery(), SmbHostDiscovery()
    first, second = smb_burst('a', 25, 0), smb_burst('b', 300, 3600)
    prefix = smb_burst('prefix', 50, 30)[25:]
    sources = {ref.key: {'native': ref.native_id} for row in [*first, *second, *prefix] for ref in row.raw}
    try:
        list(owner.consume(first))
        [peak] = list(owner.consume(second))
        publish_match(repo, 'smb-r3', owner, peak, None, sources)
        [before] = repo.candidates('smb-r3')
        for row in [*resumed.consume(first), *resumed.consume(prefix)]:
            publish_match(repo, 'smb-r3', resumed, row, None, sources)
        [after] = repo.candidates('smb-r3')
        assert after == before
        assert after['gate_results']['aggregate_summary']['episodes'] == 2
        assert after['gate_results']['aggregate_summary']['peak'] == 300
    finally:
        owner.release_state()
        resumed.release_state()
        engine.dispose()


def bridge_rows():
    return [event('net_socket', 3, native=f'bridge-{n}', offset=60+(n//2)*30, **{
        'source.ip': '10.0.0.1', 'destination.ip': f'10.3.0.{n+1}',
        'destination.port': 445, 'network.direction': 'egress', 'network.transport': 'tcp'}) for n in range(50)]


@pytest.mark.parametrize('fresh', [False, True])
def test_late_smb_bridge_keeps_historical_episode_count_without_hiding_recomputed_peak(fresh):
    first, second, bridge = smb_burst('a', 25, 0), smb_burst('b', 25, 800), bridge_rows()
    owner = SmbHostDiscovery()
    try:
        list(owner.consume(first))
        [published] = list(owner.consume(second))
        assert published.aggregate_summary['episodes'] == 2 and published.aggregate_summary['peak'] == 25
        if fresh:
            owner.release_state()
            owner = SmbHostDiscovery()
            calls = []
            def restore(group):
                calls.append(group)
                assert group == published.group_key
                return {'summary': published.aggregate_summary, 'lane': 'lead', 'events': published.events}
            owner.published_aggregate = restore
            forward = list(owner.consume([*first, *bridge, *second]))
        else:
            forward = list(owner.consume(bridge))
        matches = [*forward, *owner.finalize()]
        assert matches
        match = matches[-1]
        assert match.aggregate_summary['episodes'] >= 2
        assert match.aggregate_summary['continuity_episodes'] == 1
        assert match.aggregate_summary['peak'] == 63
        assert 'previously observed episodes connected by late records' in match.claim.lower()
        assert 'current continuity 1' in match.claim.lower()
        assert {'a-24', 'bridge-37'} <= {e.id for e in match.events}
        assert len(match.events) <= 4
        if fresh:
            assert len(calls) == 1
    finally:
        owner.release_state()


def test_fresh_later_smb_episode_is_visible_without_losing_historical_peak_or_inventing_reconstruction():
    owner = SmbHostDiscovery()
    try:
        list(owner.consume(smb_burst('a', 25, 0)))
        list(owner.consume(smb_burst('b', 25, 800)))
        list(owner.consume(bridge_rows()))
        [published] = list(owner.finalize())
        owner.release_state()
        owner = SmbHostDiscovery()
        owner.published_aggregate = lambda group: {
            'summary': published.aggregate_summary, 'lane': 'lead', 'events': published.events}
        [later] = list(owner.consume(smb_burst('new', 25, 2000)))
        assert later.aggregate_summary['episodes'] == 2 and later.aggregate_summary['peak'] == 63
        assert later.aggregate_summary['last'] > published.aggregate_summary['last']
        assert 'later qualifying window' in later.revision_reason
        assert 'last completed continuity reconstruction: 1' in later.claim.lower()
        assert {'a-24', 'bridge-37', 'new-24'} <= {e.id for e in later.events}
        assert list(owner.finalize()) == []
    finally:
        owner.release_state()


def test_restored_smb_lane_is_not_lowered_when_a_larger_peak_is_recovered():
    original, resumed = SmbHostDiscovery(), SmbHostDiscovery()
    try:
        [published] = list(original.consume(smb_burst('original', 25, 0)))
        resumed.published_aggregate = lambda group: {
            'summary': published.aggregate_summary, 'lane': 'high', 'events': published.events}
        [match] = list(resumed.consume(smb_burst('larger', 50, 3000)))
        assert match.proposed_lane == 'high' and match.aggregate_summary['peak'] == 50
        assert any('lane retained' in note.lower() for note in match.notes)
    finally:
        original.release_state()
        resumed.release_state()
