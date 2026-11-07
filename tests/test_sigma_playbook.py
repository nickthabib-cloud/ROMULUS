"""Local Sigma execution retains attribution, scope, and bounded indexed dispatch."""
import tracemalloc
from copy import deepcopy

import pytest

from romulus.content.sigma_parser import ast_digest, parse_rule
from romulus.detect.sigma import SigmaEventIndex, SigmaRule
from tests.test_indicator_content_matching import VALUES
from tests.test_indicators import net_event


def row(number=0):
    parsed = parse_rule({'title': 'Synthetic process', 'logsource': {'product': 'windows', 'category': 'process_creation'},
        'detection': {'selection': {'Image|endswith': '\\evil.exe'}, 'condition': 'selection'}})
    assert parsed['reasons'] == []
    return {'id': str(number), 'title': 'Synthetic process', 'author': 'In-house tests',
            'upstream': 'Local tests', 'upstream_path': 'synthetic/rule.yaml', 'upstream_commit': 'a'*40,
            'ast': parsed['ast'], 'mapping': parsed['mapping'], 'digest': ast_digest(parsed['ast']),
            'tags': ['attack.t1059'], 'status': 'active', 'level': 'high', 'lane': 'lead', 'activation_reason': ''}


def test_match_cites_attribution_and_typed_fields_without_promoting_sigma_level():
    owner = SigmaRule(row())
    event = net_event('process_exec', host__os__family='windows', event__code=1,
        event__channel='Microsoft-Windows-Sysmon/Operational', event__provider='Microsoft-Windows-Sysmon',
        process__executable=r'C:\Tools\evil.exe')
    [match] = list(owner.consume([event]))
    assert match.proposed_lane == 'lead'
    assert 'matched the Sigma rule Synthetic process (synthetic/rule.yaml@'+'a'*40+')' in match.claim
    assert 'In-house tests' in str(match.notes)
    assert any(field.field == 'process.executable' for field in match.predicate)
    assert owner.assures_negative is False
    assert owner.match_evaluations == 1


def test_class_scope_rejects_same_event_code_from_other_provider_and_unrelated_family():
    owner = SigmaRule(row())
    wrong = net_event('process_exec', host__os__family='windows', event__code=1,
        event__channel='Other', event__provider='Other', process__executable=r'C:\evil.exe')
    unrelated = net_event('file_transfer', file__hash__sha256=VALUES['sha256'])
    assert list(owner.consume([wrong, unrelated])) == []
    assert owner.match_evaluations == 0


def test_explicit_high_override_survives_the_real_publication_policy():
    from romulus.evidence.windows import normalize_windows
    from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
    from romulus.hunt.publish import publish_match
    from tests.test_sweep import _repo
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
    owner = SigmaRule(dict(row(), lane='high', activation_reason='Mission-approved predicate'))
    hit = windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, 'ws01', 1,
        '2026-01-02T03:04:05Z', {'Image': r'C:\Tools\evil.exe', 'ProcessId': '123'}), 'elastic_agent')
    [match] = list(owner.consume([normalize_windows(hit)]))
    repo = _repo()
    try:
        published = publish_match(repo, 'h1', owner, match, None, {hit['_index']+'/'+hit['_id']: hit['_source']})
        assert published['lane'] == 'high'
        assert 'Mission-approved predicate' in str(published['gate_results']['_notes'])
    finally:
        repo.engine.dispose()


def test_hundreds_of_rules_share_one_native_class_with_matching_bounded_state(monkeypatch):
    monkeypatch.setattr(SigmaRule, 'HOT', 8)
    monkeypatch.setattr(SigmaRule, 'TRIM_EVERY', 16)
    owners = [SigmaRule(row(number)) for number in range(300)]
    events = [net_event('process_exec', str(number), host__os__family='windows', event__code=1,
        event__channel='Microsoft-Windows-Sysmon/Operational', event__provider='Microsoft-Windows-Sysmon',
        process__executable=r'C:\Tools\evil.exe' if number < 60 else r'C:\Tools\benign.exe',
        process__command_line='evil.exe --'+str(number % 5)) for number in range(100)]
    try:
        index = SigmaEventIndex(events)
        for owner in owners:
            [match] = owner.consume_scoped_partition(index.for_rule(owner))
            assert match.aggregate_summary['count'] == 60
            assert '5 distinct command lines, 5 cited' in match.claim
            assert len(match.events) <= owner.EXAMPLE_LIMIT
            owner.drain_staged()
            assert len(owner.delivered.hot) <= 8 and owner.delivered.on_disk > 0
            assert len(owner.command_keys.hot) <= 8
            assert len(owner.groups.hot) <= 1 and len(owner.bounds.pending) <= 2
        assert sum(owner.match_evaluations for owner in owners) == 30000
        assert index.records == 100 and index.buckets == 1
    finally:
        for owner in owners:
            owner.close_spill()


@pytest.mark.slow
@pytest.mark.parametrize('classes', [1000, 2000])
def test_two_thousand_rules_and_hundred_thousand_events_use_indexed_bounded_state(classes):
    # Input events are already owned by the sweep. Measure additional rule/index state.
    events = [net_event('process_exec', str(i), host__os__family='windows', event__code=i % classes,
        event__channel='Synthetic', event__provider='Synthetic', process__executable=r'C:\benign.exe')
        for i in range(100000)]
    tracemalloc.start()
    try:
        template = row()
        owners = []
        for i in range(2000):
            metadata = deepcopy(template)
            metadata['id'] = str(i)
            metadata['mapping'] = dict(template['mapping'], windows_event_classes=[['Synthetic', 'Synthetic', i % classes]],
                                       event_codes=[str(i % classes)])
            metadata['ast']['scope'].update(metadata['mapping'])
            owners.append(SigmaRule(metadata))
        index = SigmaEventIndex(events)
        for owner in owners:
            assert list(owner.consume_scoped_partition(index.for_rule(owner))) == []
        assert sum(owner.match_evaluations for owner in owners) == 100000*(2000//classes)
        assert index.records == 100000
        assert index.buckets == classes
        assert tracemalloc.get_traced_memory()[1] < 64 * 1024 * 1024
    finally:
        tracemalloc.stop()
