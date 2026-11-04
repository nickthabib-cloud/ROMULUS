"""Concrete SQL instance names from bounded inventory reach typed raw retrieval."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.windows_catalog_events import MssqlXpCmdshellEnabled
from romulus.evidence.windows_catalog import lookup_event_class
from romulus.hunt import sweep as sw
from romulus.sources.compile import compile_es
from romulus.sources.models import Completeness, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from tests.test_sweep import _repo
from tests.windows_fixtures import LogicalWindowsEvent, windows_hit

START = datetime(2026, 1, 2, tzinfo=UTC)


def contract():
    return contract_from_types('logs-sql', {'@timestamp': 'date', 'winlog.channel': 'keyword',
        'winlog.provider_name': 'keyword', 'winlog.event_id': 'long', 'winlog.computer_name': 'keyword',
        'winlog.record_id': 'long', 'winlog.event_data': 'flattened'}, role='host', os_family='windows')


def prepare(tmp_path, monkeypatch, provider='MSSQL$INSTANCE', *, partial=False, channel='Application'):
    c = contract()
    rule = MssqlXpCmdshellEnabled()
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [rule])
    window = Window(start=START, end=START + timedelta(hours=1))
    sweep = sw.Sweep(_repo(), None, 'h1', window, {c.target: c}, stage_dir=tmp_path)
    def execute(client, intent, mapping):
        assert intent.purpose == 'windows event class inventory'
        assert intent.max_records == 10000
        return SearchOutcome(target=c.target, fingerprint='inventory', started_at=START, ended_at=START,
            completeness=Completeness.partial if partial else Completeness.complete,
            reasons=['aggregate_bucket_cap:10000'] if partial else [],
            buckets=[{'key': {'event.channel': channel, 'event.provider': provider, 'event.code': 15457}, 'count': 1}])
    monkeypatch.setattr(sw, 'execute', execute)
    sweep._prepare_windows_inventory(c.target, c)
    return sweep, c, window


@pytest.mark.parametrize('provider', ['MSSQL$INSTANCE', 'mssql$NamedInstance', 'MSSQL$OTHER$AUDIT'])
def test_concrete_instance_triple_is_retrieved_and_compiled(tmp_path, monkeypatch, provider):
    sweep, c, window = prepare(tmp_path, monkeypatch, provider)
    try:
        groups = sweep._any_of_for(c.target, c)
        assert any({item.field: item.value for item in group} == {
            'event.channel': 'Application', 'event.provider': provider, 'event.code': 15457} for group in groups)
        query = compile_es(SearchIntent(kind='raw', target=c.target, window=window, any_of=groups), c)
        compiled = json.dumps(query.body)
        assert provider in compiled
        assert 'MSSQL$*' not in compiled
        assert not sweep.stats.get('windows_unassessed', {}).get(c.target)
    finally:
        sweep.close_stage()


@pytest.mark.parametrize('channel,provider', [('System', 'MSSQL$INSTANCE'), ('Application', 'MSSQL_FAKE')])
def test_instance_fallback_does_not_admit_other_channels_or_provider_prefixes(tmp_path, monkeypatch, channel, provider):
    sweep, c, _ = prepare(tmp_path, monkeypatch, provider, channel=channel)
    try:
        assert not any(any(p.field == 'event.provider' and p.value == provider for p in group)
                       for group in sweep._any_of_for(c.target, c))
        assert sweep.stats['windows_unassessed'][c.target]
    finally:
        sweep.close_stage()


def test_partial_instance_inventory_stays_named(tmp_path, monkeypatch):
    sweep, c, _ = prepare(tmp_path, monkeypatch, partial=True)
    try:
        assert any('aggregate_bucket_cap' in reason for reason in sweep._windows_inventory_reasons[c.target])
        assert any(any(p.value == 'MSSQL$INSTANCE' for p in group) for group in sweep._any_of_for(c.target, c))
    finally:
        sweep.close_stage()


def test_named_instance_is_not_a_missing_default_instance_in_coverage(tmp_path, monkeypatch):
    sweep, c, _ = prepare(tmp_path, monkeypatch)
    try:
        reasons = sweep._windows_rule_reasons(c.target, c, sweep.pack[0], [], [])
        assert not any('event class absent from source inventory: Application|MSSQLSERVER|15457' in item
                       for item in reasons)
    finally:
        sweep.close_stage()


def test_unsupported_only_selected_class_cannot_turn_into_an_unfiltered_query(tmp_path, monkeypatch):
    sweep, c, window = prepare(tmp_path, monkeypatch)
    c = contract_from_types(c.target, {'@timestamp': 'date', 'winlog.channel': 'keyword',
        'winlog.provider_name': 'keyword', 'winlog.event_id': 'long'}, role='host', os_family='windows')
    event_class = lookup_event_class('Security', 'Microsoft-Windows-Security-Auditing', 5156)
    assert event_class
    monkeypatch.setattr(sw, 'EVENT_CLASSES', (event_class,))
    sweep._windows_read_tokens[c.target] = {event_class.token}
    sweep._windows_dynamic_classes[c.target] = ()
    try:
        groups = sweep._any_of_for(c.target, c)
        assert groups, 'An empty any_of would compile as unfiltered raw retrieval'
        assert len(groups) == 1
        assert {(item.field, item.op) for item in groups[0]} == {
            ('event.code', 'exists'), ('event.code', 'missing')}
        compiled = json.dumps(compile_es(SearchIntent(kind='raw', target=c.target, window=window,
                                                    any_of=groups), c).body)
        assert 'must_not' in compiled and 'exists' in compiled
        assert any('WFP tunnel records not fetched' in item for item in sweep._windows_inventory_reasons[c.target])
    finally:
        sweep.close_stage()


def test_named_instance_record_publishes_through_selective_sweep(tmp_path, monkeypatch):
    sweep, c, window = prepare(tmp_path, monkeypatch)
    hit = windows_hit(LogicalWindowsEvent('Application', 'MSSQL$INSTANCE', 15457, 'db.example.test', 1,
        (START + timedelta(minutes=5)).isoformat(), {'param1': 'xp_cmdshell', 'param2': '0', 'param3': '1'}),
        'winlogbeat_8')
    hit['_index'] = c.target
    def execute(client, intent, mapping):
        if intent.kind == 'aggregate':
            # Complete channel continuity metadata for this one native record.
            return SearchOutcome(target=c.target, fingerprint='continuity', started_at=START, ended_at=START,
                completeness=Completeness.complete, total=1, total_relation='eq',
                buckets=[{'key': {'@timestamp': (START + timedelta(minutes=5)).isoformat(),
                    'host.name': 'db.example.test', 'event.channel': 'Application', 'winlog.record_id': 1},
                    'count': 1, 'first': (START + timedelta(minutes=5)).isoformat(),
                    'last': (START + timedelta(minutes=5)).isoformat()}])
        assert any({p.field: p.value for p in group}.get('event.provider') == 'MSSQL$INSTANCE'
                   for group in intent.any_of)
        return SearchOutcome(target=c.target, fingerprint='native', started_at=START, ended_at=START,
            completeness=Completeness.complete, total=1, total_relation='eq', returned=1, records=[hit])
    monkeypatch.setattr(sw, 'execute', execute)
    try:
        sweep.run_partition(c.target, c, [], window, est=1, any_of=sweep._any_of_for(c.target, c))
        sweep.finalize()
        [row] = sweep.repo.candidates('h1')
        assert row['lane'] == 'high' and 'MSSQL$INSTANCE' in row['claim']
        assert row['event_ids']
    finally:
        sweep.close_stage()
