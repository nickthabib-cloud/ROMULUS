"""Reported marker multi-fields must keep bounded Zeek readers searchable."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.zeek_catalog import CONN
from romulus.hunt.zeek_sources import source_groups
from romulus.sources.compile import build_query
from romulus.sources.models import SearchIntent, Window
from romulus.sources.profile import contract_from_types


@pytest.mark.parametrize('shape,markers', [
    ('plain', {'_path': 'conn'}),
    ('malcolm', {'event.provider': 'zeek', 'event.dataset': 'conn'}),
    ('elastic', {'data_stream.dataset': 'zeek.connection'}),
    ('security_onion', {'event.module': 'zeek', 'event.dataset': 'conn'}),
])
@pytest.mark.parametrize('suffix', ['keyword', 'exact_value'])
def test_exact_marker_multifields_are_used_by_shared_source_queries(shape, markers, suffix):
    types = {name: 'text' for name in markers}
    types.update({name+'.'+suffix: 'keyword' for name in markers})
    contract = contract_from_types('network', types)
    if shape == 'plain':
        contract = contract.model_copy(update={'zeek_sensor': 'sensor'})
    groups = source_groups(contract, CONN, shape)
    assert groups
    intent = SearchIntent(kind='raw', target='network',
        window=Window(start='2026-01-01T00:00:00Z', end='2026-01-01T01:00:00Z'), any_of=groups)
    query = str(build_query(intent, contract))
    for marker in markers:
        assert marker+'.'+suffix in query


@pytest.mark.parametrize('shape', ['plain','elastic','malcolm','security_onion'])
def test_lookback_overlap_predicate_keeps_shape_duration_units(shape):
    from romulus.hunt.zeek_sources import overlap_groups
    from tests.fixtures import zeek_factory as zf
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import matches
    writer = getattr(zf,shape)
    long = writer(replace(zf.Conn(),ts=zf.T0-3600,duration=7200),'long')
    short = writer(replace(zf.Conn(),ts=zf.T0-3600,duration=1),'short')
    contract = NativePivot(shape,[long,short]).contracts['network'].model_copy(update={
        'time_field':'ts' if shape=='plain' else '@timestamp'})
    start = datetime.fromtimestamp(zf.T0,UTC)
    part = Window(start=start-timedelta(hours=1),end=start-timedelta(minutes=1))
    groups = overlap_groups(contract,source_groups(contract,CONN,shape),start,part.end,shape=shape)
    query = build_query(SearchIntent(kind='raw',target='network',window=part,any_of=groups),contract)
    assert matches(query,long['_source'])
    assert not matches(query,short['_source'])
