"""Imported Sigma positives fold into bounded, cited behavior groups."""
from datetime import timedelta

import pytest

from romulus.content.sigma_parser import parse_rule
from romulus.detect.sigma import SigmaEventIndex, SigmaRule
from romulus.evidence.typed import RawRef
from romulus.hunt.publish import publish_match
from tests.test_indicators import net_event
from tests.test_sigma_playbook import row
from tests.test_sweep import _repo


def process(number=0, *, host='sensor', parent=r'C:\Windows\cmd.exe', command='evil.exe --one'):
    event = net_event('process_exec', str(number), host__os__family='windows', event__code=1,
        event__channel='Microsoft-Windows-Sysmon/Operational', event__provider='Microsoft-Windows-Sysmon',
        process__executable=r'C:\Tools\evil.exe', process__parent__executable=parent,
        process__command_line=command)
    return event.model_copy(update={'host': host, 'ts': event.ts+timedelta(seconds=number)})


@pytest.mark.slow
def test_two_hundred_thousand_matching_records_emit_one_group_per_batch():
    owner = SigmaRule(row())
    template = process()
    events = (template.model_copy(update={'id': str(number),
        'raw': [RawRef(target='net', native_id=str(number))],
        'ts': template.ts+timedelta(seconds=number)}) for number in range(200000))
    try:
        assert sum(1 for _ in owner.consume(events)) == 1
    finally:
        owner.close_spill()


@pytest.mark.parametrize('records', [500, pytest.param(200000, marks=pytest.mark.slow)])
def test_real_repository_retains_one_exact_group_with_bounded_distinct_commands(records):
    owner = SigmaRule(dict(row(), lane='high', activation_reason='Mission-approved behavior'))
    repo = _repo()
    staged = {}
    owner.bind_loader(lambda ids: [staged[identity] for identity in ids if identity in staged])
    template = process()
    def events(start, end):
        for number in range(start, end):
            event = template.model_copy(update={'id': str(number),
                'raw': [RawRef(target='net', native_id=str(number))],
                'ts': template.ts+timedelta(seconds=number)})
            # A second command appears after the first batch's first two witnesses.
            event.fields = dict(template.fields)
            event.fields['process.command_line'] = template.fields['process.command_line'].model_copy(
                update={'value': 'evil.exe --'+str(number % 4)})
            yield event
    def deliver(batch):
        matches = list(owner.consume(batch))
        for match in matches:
            sources = {ref.key: {'serial': event.id} for event in match.events for ref in event.raw}
            publish_match(repo, 'h1', owner, match, None, sources)
        staged.update((event.id, event) for event in owner.drain_staged())
        return matches
    try:
        assert len(deliver(events(0, records//2))) == 1
        assert len(deliver(events(records//2, records))) == 1
        [candidate] = repo.candidates('h1')
        summary = candidate['gate_results']['aggregate_summary']
        assert summary['count'] == records
        assert summary['first'] == template.ts.timestamp()
        assert summary['last'] == (template.ts+timedelta(seconds=records-1)).timestamp()
        assert candidate['lane'] == 'high'
        assert candidate['group_key'].startswith('sigma-fold:')
        assert len(candidate['event_ids']) <= owner.EXAMPLE_LIMIT
        citations = repo.citation_events('h1', candidate['event_ids'])
        assert {item['event']['fields']['process.command_line']['value'] for item in citations} == {
            'evil.exe --'+str(number) for number in range(4)}
        assert candidate['gate_results']['_revision']['count'] == 1
        assert deliver(events(0, records)) == []
        assert list(owner.finalize()) == []
        assert len(owner.delivered.hot) <= owner.HOT
        if records > owner.HOT:
            assert owner.delivered.on_disk > 0
    finally:
        owner.close_spill()
        repo.engine.dispose()


def test_grouping_uses_executable_parent_and_host_but_keeps_distinct_commands_together():
    owner = SigmaRule(row())
    try:
        matches = list(owner.consume([process(0), process(1, command='evil.exe --two'),
            process(2, parent=r'C:\Windows\powershell.exe'), process(3, host='another')]))
        assert sorted(match.aggregate_summary['count'] for match in matches) == [1, 1, 2]
        assert len({match.group_key for match in matches}) == 3
        assert all(field.origin for match in matches for field in match.predicate)
    finally:
        owner.close_spill()


@pytest.mark.parametrize('category,code,field,label', [
    ('process_creation', 1, 'process.command_line', 'command lines'),
    ('ps_script', 4104, 'script.text', 'script texts'),
    ('image_load', 7, 'process.command_line', 'command lines'),
])
def test_native_folds_count_distinct_payloads_and_cite_first_and_last_arrivals(category, code, field, label):
    from romulus.evidence.windows import normalize_windows
    from romulus.evidence.windows_catalog import (
        POWERSHELL_CHANNEL,
        POWERSHELL_PROVIDER,
        SYSMON,
        SYSMON_CHANNEL,
    )
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
    parsed = parse_rule({'title': 'Native payloads', 'logsource': {'product': 'windows', 'category': category},
        'detection': {'selection': {'EventID': code}, 'condition': 'selection'}})
    owner = SigmaRule(dict(row(), ast=parsed['ast'], mapping=parsed['mapping']))
    repo = _repo()
    staged = {}
    owner.bind_loader(lambda ids: [staged[identity] for identity in ids if identity in staged])
    channel, provider = ((POWERSHELL_CHANNEL, POWERSHELL_PROVIDER) if category == 'ps_script'
                         else (SYSMON_CHANNEL, SYSMON))
    events = []
    for number in range(40):
        value = 'evil.exe --'+str(number % 30)
        data = {'Image': r'C:\Tools\evil.exe', 'ParentImage': r'C:\Windows\cmd.exe', 'CommandLine': value,
                'ImageLoaded': r'C:\Tools\evil.dll', 'ScriptBlockText': value, 'ScriptBlockId': 'block-'+str(number)}
        if category == 'ps_script':
            data.pop('CommandLine')
        event = normalize_windows(windows_hit(LogicalWindowsEvent(channel, provider, code, 'ws01', number+1,
            (process().ts+timedelta(seconds=number)).isoformat(), data), 'elastic_agent'))
        assert event.get(field) == value
        events.append(event)
    try:
        for start in range(0, 40, 10):
            [match] = owner.consume(events[start:start+10])
            sources = {ref.key: {'serial': event.id} for event in match.events for ref in event.raw}
            publish_match(repo, 'h1', owner, match, None, sources)
            staged.update((event.id, event) for event in owner.drain_staged())
        [candidate] = repo.candidates('h1')
        citations = repo.citation_events('h1', candidate['event_ids'])
        cited = {item['event']['fields'][field]['value'] for item in citations}
        assert {f'evil.exe --{number}' for number in [*range(8), *range(22, 30)]} <= cited
        assert len(candidate['event_ids']) <= owner.EXAMPLE_LIMIT
        assert f'30 distinct {label}, {len(cited)} cited' in candidate['claim']
        assert candidate['gate_results']['aggregate_summary']['count'] == 40
    finally:
        owner.close_spill()
        repo.engine.dispose()


def test_distinct_command_identity_spills_and_survives_repeated_values():
    owner = SigmaRule(row())
    try:
        [match] = owner.consume(process(number, command='evil.exe --'+str(number % 700)) for number in range(1400))
        assert '700 distinct command lines, 16 cited' in match.claim
        assert match.aggregate_summary['count'] == 1400
        assert owner.command_keys.on_disk > 0
        assert len(owner.command_keys.hot) <= owner.HOT
        assert len(owner._pending) <= 2
        assert len(owner._command_pending) <= 1
        assert len(owner.drain_staged()) <= owner.EXAMPLE_LIMIT+2
    finally:
        owner.close_spill()


def test_native_image_loads_keep_loaded_paths_separate_without_inventing_commands():
    from romulus.evidence.windows import normalize_windows
    from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
    parsed = parse_rule({'title': 'Native image loads',
        'logsource': {'product': 'windows', 'category': 'image_load'},
        'detection': {'selection': {'EventID': 7}, 'condition': 'selection'}})
    owner = SigmaRule(dict(row(), ast=parsed['ast'], mapping=parsed['mapping']))
    events = [normalize_windows(windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 7, 'ws01', number+1,
        process().ts.isoformat(), {'Image': r'C:\Tools\loader.exe', 'ImageLoaded': path}), 'elastic_agent'))
        for number, path in enumerate([r'C:\Tools\one.dll', r'C:\Tools\two.dll'])]
    try:
        matches = owner.consume(events)
        assert len(matches) == 2 and all(match.aggregate_summary['count'] == 1 for match in matches)
        assert all('distinct command lines' not in match.claim for match in matches)
        assert len(owner.command_keys) == 0
    finally:
        owner.close_spill()


@pytest.mark.parametrize('category,family,field,first,second', [
    ('network_connection', 'net_socket', 'destination.ip', '192.0.2.1', '192.0.2.2'),
    ('network_connection', 'net_socket', 'destination.hostname', 'one.example', 'two.example'),
    ('dns', 'dns_query', 'dns.question.name', 'one.example', 'two.example'),
    ('file_event', 'file_change', 'file.path', r'C:\One\file.exe', r'C:\Two\file.exe'),
    ('registry_set', 'registry_change', 'registry.path', r'HKLM\One\Value', r'HKLM\Two\Value'),
])
def test_category_group_keys_use_typed_targets(category, family, field, first, second):
    metadata = row()
    metadata['mapping'] = dict(metadata['mapping'], category=category)
    owner = SigmaRule(metadata)
    one = net_event(family, 'one', **{field.replace('.', '__'): first})
    two = net_event(family, 'two', **{field.replace('.', '__'): second})
    assert owner._key(one) != owner._key(two)
    assert owner._key(one) == owner._key(one.model_copy(update={'id': 'other'}))
    assert owner.anchor_class == ('network_observation' if category in {'network_connection', 'dns'} else 'execution')


def test_publication_budget_retains_all_additional_positives_in_one_strong_summary():
    owner = SigmaRule(dict(row(), lane='high', activation_reason='Mission-approved behavior'))
    owner.PUBLICATION_LIMIT = 2
    owner.HOT = 2
    owner.TRIM_EVERY = 2
    try:
        matches = list(owner.consume(process(number, host='host-'+str(number)) for number in range(10)))
        assert len(matches) == 3
        [summary] = [match for match in matches if match.group_key.startswith('sigma-overflow:')]
        assert summary.proposed_lane == 'high' and summary.aggregate_summary['count'] == 8
        assert owner.overflow.groups == 8
        assert '8 additional group(s)' in ' '.join(owner.limit_reasons())
        assert '8 matching record(s)' in ' '.join(owner.partition_coverage_notes())
        assert sum(match.aggregate_summary['count'] for match in matches) == 10
        assert 'their separate candidates are withheld' in summary.claim
    finally:
        owner.close_spill()


def test_later_lead_member_and_fresh_replay_cannot_demote_a_published_high():
    repo = _repo()
    metadata = dict(row(), lane='high', activation_reason='Mission-approved behavior')
    owner = SigmaRule(metadata)
    replay = SigmaRule(dict(metadata, lane='lead', activation_reason=''))
    try:
        for match in owner.consume([process(0), process(1)]):
            publish_match(repo, 'h1', owner, match, None, {'net/'+event.id: {} for event in match.events})
        owner.lane = 'lead'
        for match in owner.consume([process(2)]):
            assert match.proposed_lane == 'high'
            publish_match(repo, 'h1', owner, match, None, {'net/'+event.id: {} for event in match.events})
        for match in replay.consume([process(0)]):
            publish_match(repo, 'h1', replay, match, None, {'net/'+event.id: {} for event in match.events})
        [candidate] = repo.candidates('h1')
        assert candidate['lane'] == 'high'
        assert candidate['gate_results']['aggregate_summary']['count'] == 3
    finally:
        owner.close_spill()
        replay.close_spill()
        repo.engine.dispose()


def test_missing_stage_citations_preserve_positive_identity_provenance_and_lane():
    owner = SigmaRule(dict(row(), lane='high', activation_reason='Mission-approved behavior'))
    try:
        [original] = list(owner.consume([process(0)]))
        owner.drain_staged()
        owner.bind_loader(lambda ids: [])
        [revision] = list(owner.consume([process(1)]))
        assert revision.citation_unavailable and revision.proposed_lane == 'high'
        assert revision.group_key == original.group_key
        assert revision.aggregate_summary['count'] == 2
        assert 'synthetic/rule.yaml@' in revision.claim
        assert 'In-house tests' in str(revision.notes)
    finally:
        owner.close_spill()


def test_consume_returns_bounded_matches_for_script_finalize_and_uncertain_flow_delivery():
    owner = SigmaRule(row())
    try:
        assert len(owner.consume([process(0)])) == 1
        [match] = owner.consume_unaggregated([process(1)], 'Canonical connection identity unavailable')
        assert match.aggregate_summary['count'] == 2
        assert 'matching delivery record(s)' in match.claim
        assert 'not unique connections' in ' '.join(owner.limit_reasons())
    finally:
        owner.close_spill()


def test_undecidable_comparison_exposes_named_partial_coverage():
    parsed = parse_rule({'title': 'Missing original image name',
        'logsource': {'product': 'windows', 'category': 'process_creation'},
        'detection': {'selection': {'OriginalFileName': None}, 'condition': 'selection'}})
    metadata = dict(row(), ast=parsed['ast'], mapping=parsed['mapping'])
    owner = SigmaRule(metadata)
    event = net_event('process_exec', 'missing', host__os__family='windows', event__code=4688,
        event__channel='Security', event__provider='Microsoft-Windows-Security-Auditing',
        process__executable=r'C:\Tools\evil.exe')
    assert owner.consume([event]) == []
    assert owner.missing_required == 1
    assert 'undecidable' in ' '.join(owner.limit_reasons())
    assert 'typed_field_unavailable_for_event_class' in ' '.join(owner.partition_coverage_notes())


def test_native_class_routing_is_sorted_independently_of_frozenset_order():
    owner = SigmaRule(row())
    owner._classes = frozenset({('z', 'provider', '1'), ('a', 'provider', '2')})
    owner.families = ('process_exec',)
    events = [net_event('process_exec', key, host__os__family='windows', event__channel=channel,
                       event__provider='provider', event__code=code)
              for key, channel, code in [('z', 'z', 1), ('a', 'a', 2)]]
    assert [event.id for event in SigmaEventIndex(events).for_rule(owner)] == ['a', 'z']


@pytest.mark.slow
def test_hundred_thousand_hosts_use_disk_for_identity_state_and_one_overflow_candidate():
    owner = SigmaRule(row())
    owner.PUBLICATION_LIMIT = 4
    template = process()
    events = (template.model_copy(update={'id': str(number), 'host': 'host-'+str(number)})
              for number in range(100000))
    try:
        matches = list(owner.consume(events))
        assert len(matches) == 5
        assert sum(match.aggregate_summary['count'] for match in matches) == 100000
        assert owner.overflow.groups == 99996
        assert owner.overflow_keys.on_disk > 0 and owner.delivered.on_disk > 0
        assert len(owner.overflow_keys.hot) <= owner.HOT
        assert len(owner.delivered.hot) <= owner.HOT
        assert len(owner._pending) <= (owner.PUBLICATION_LIMIT+1)*18
        assert len(owner.bounds.pending) <= (owner.PUBLICATION_LIMIT+1)*2
    finally:
        owner.close_spill()
