"""Exact source-profile aggregations and conservative integer-duration overlap."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.hunt.zeek_sources import overlap_groups
from romulus.sources.compile import build_query
from romulus.sources.models import SearchIntent, Window
from romulus.sources.profile import build_profile, contract_from_types, flatten_mapping
from tests.test_zeek_profile import MALCOLM_FIELDS, _bucket, _Client, _mapping
from tests.zeek_source_support import matches


class StrictProfileClient(_Client):
    def __init__(self, fields, protocols, pages, text_fields):
        super().__init__(fields, protocols, pages)
        self.text_fields = text_fields

    def mapping(self, target):
        mapping = _mapping(*self.fields)
        for name, suffix in self.text_fields.items():
            props = mapping['idx']['mappings']['properties']
            parts = name.split('.')
            for part in parts[:-1]:
                props = props[part]['properties']
            props[parts[-1]] = {'type': 'text'}
            if suffix:
                props[parts[-1]]['fields'] = {suffix: {'type': 'keyword'}}
        return mapping

    def search(self, target, body):
        types = flatten_mapping(self.mapping(target))
        def check(value):
            if isinstance(value, dict):
                if isinstance(value.get('terms'), dict) and 'field' in value['terms']:
                    field = value['terms']['field']
                    assert types.get(field) != 'text', f'Elasticsearch rejects terms on text field {field}'
                for item in value.values():
                    check(item)
            elif isinstance(value, list):
                for item in value:
                    check(item)
        check(body)
        response = super().search(target, body)
        response['aggregations'] = {key: value for key, value in response.get('aggregations', {}).items()
                                    if key in body['aggs']}
        return response


@pytest.mark.parametrize('marker', ['event.dataset', 'data_stream.dataset'])
@pytest.mark.parametrize('suffix', ['keyword', 'exact_value'])
def test_profile_dataset_terms_uses_reported_exact_multifield(marker, suffix):
    client = StrictProfileClient(('@timestamp', marker, 'host.name', 'zeek.uid'),
                                 {'zeek.conn': 100}, [], {marker: suffix})
    profile, _contract = build_profile(client, 'idx')
    assert client.bodies[0]['aggs']['ds']['terms']['field'] == marker + '.' + suffix
    assert profile.datasets == {'zeek.conn': 100}


def test_profile_dataset_text_without_exact_field_is_named_and_not_aggregated():
    client = StrictProfileClient(('@timestamp', 'event.dataset', 'host.name', 'zeek.uid'),
                                 {'zeek.conn': 100}, [], {'event.dataset': None})
    profile, _contract = build_profile(client, 'idx')
    assert all('ds' not in body['aggs'] for body in client.bodies)
    assert profile.datasets == {}
    assert any(note.startswith('ds inventory truncated') and 'event.dataset' in note for note in profile.notes)


def test_mixed_provider_inventory_resolves_both_text_multifields():
    client = StrictProfileClient(MALCOLM_FIELDS, {'tcp': 100},
        [{'buckets': [_bucket('zeek', 'conn', 100)]}],
        {'event.dataset': 'exact_value', 'event.provider': 'keyword'})
    profile, _contract = build_profile(client, 'idx')
    [inventory] = [body['aggs']['inventory']['composite'] for body in client.bodies if 'inventory' in body['aggs']]
    assert inventory['sources'] == [
        {'provider': {'terms': {'field': 'event.provider.keyword', 'missing_bucket': True}}},
        {'dataset': {'terms': {'field': 'event.dataset.exact_value', 'missing_bucket': True}}}]
    assert profile.datasets == {'zeek:conn': 100}


@pytest.mark.parametrize('kind', ['long', 'integer', 'short'])
def test_truncated_integer_duration_keeps_a_possibly_overlapping_connection(kind):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    contract = contract_from_types('network', {'@timestamp': 'date', 'duration': kind})
    groups = overlap_groups(contract, [[]], start, start-timedelta(seconds=1.9), shape='plain')
    intent = SearchIntent(kind='raw', target='network', window=Window(start=start-timedelta(hours=1), end=start),
                          any_of=groups)
    query = build_query(intent, contract)
    source = {'@timestamp': (start-timedelta(seconds=2)).isoformat(), 'duration': 1}
    assert matches(query, source)
    assert not matches(query, {**source, 'duration': 0})


def test_fractional_duration_keeps_fractional_threshold():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    contract = contract_from_types('network', {'duration': 'double'})
    groups = overlap_groups(contract, [[]], start, start-timedelta(seconds=1.9), shape='plain')
    [threshold] = [predicate.value for group in groups for predicate in group if predicate.op == 'gte']
    assert threshold == pytest.approx(1.9)

def test_profile_host_text_uses_its_exact_multifield_too():
    client = StrictProfileClient(('@timestamp', 'event.dataset', 'host.name', 'zeek.uid'),
                                 {'zeek.conn': 100}, [], {'host.name': 'keyword'})
    profile, contract = build_profile(client, 'idx')
    assert client.bodies[0]['aggs']['hosts']['terms']['field'] == 'host.name.keyword'
    assert profile.hosts and contract.host_inventory_complete


def test_unsearchable_mixed_inventory_is_named_instead_of_rejecting_hunt_creation():
    from romulus.hunt import sweep as sw
    client = StrictProfileClient(MALCOLM_FIELDS, {'tcp': 100}, [], {'event.provider': None})
    profile, contract = build_profile(client, 'idx')
    assert not any('inventory' in body['aggs'] for body in client.bodies)
    assert any(note.startswith('ds inventory truncated') for note in profile.notes)
    assert sw.delivered_families(profile.model_dump(mode='json'), contract) == sw._ROLE_FAMILIES['network']
