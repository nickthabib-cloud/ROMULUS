"""Exact polling exclusion retains unknown codes, missing fields, and exception branches."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.sources.compile import CompileError, build_query
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.sources.profile import OPS_BY_TYPE, FieldContract, FieldSpec


def contract(kind='keyword',natives=()):
    return FieldContract(target='ics',role='network',fields={
        'func':FieldSpec(native='func',natives=natives,type=kind,
                         ops=sorted(OPS_BY_TYPE[kind]),aggregatable=True)})


def intent(value):
    start=datetime(2026,1,1,tzinfo=UTC)
    return SearchIntent(kind='raw',target='ics',window=Window(start=start,end=start+timedelta(hours=1)),
        filters=[Predicate(field='func',op='not_in',value=value)])


def test_exact_not_in_compiles_to_native_terms_exclusion():
    query=build_query(intent(['READ_HOLDING_REGISTERS','READ_INPUT_REGISTERS']),contract())
    assert query['bool']['filter'][1]=={'bool':{'must_not':[
        {'terms':{'func':['READ_HOLDING_REGISTERS','READ_INPUT_REGISTERS']}}]}}


def test_alias_exclusion_requires_every_native_alias_to_be_nonread():
    query=build_query(intent([3,4]),contract('long',('func','func_old')))
    assert query['bool']['filter'][1]=={'bool':{'filter':[
        {'bool':{'must_not':[{'terms':{'func':[3,4]}}]}},
        {'bool':{'must_not':[{'terms':{'func_old':[3,4]}}]}}]}}


@pytest.mark.parametrize('values',[[],list(range(1001))])
def test_empty_or_unbounded_exclusions_are_refused(values):
    with pytest.raises(CompileError):
        build_query(intent(values),contract('long'))


def test_analyzed_text_cannot_filter_reads_and_requires_unfiltered_fallback():
    with pytest.raises(CompileError,match='superset'):
        build_query(intent(['READ']),contract('text'))
