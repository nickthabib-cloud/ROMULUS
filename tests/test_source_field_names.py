"""Source field names no typed predicate can carry never crash a hunt and never change a query's meaning.

Zeek pipelines add fields such as `zeek.dns.@proc`, `@stream` and `@system`, and other shippers write names with
hyphens or spaces. A field contract keeps them as record fields that no predicate searches; where such a field was
an exclusion marker, raw reads stay exact (each record's layout is recognized from the record) and aggregates that
cannot check records say the log's visibility is unresolved."""
import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.zeek import AMBIGUOUS, zeek_record
from romulus.evidence.zeek_catalog import ELASTIC, PLAIN, SECURITY_ONION, SHAPES, ZEEK_LOGS
from romulus.hunt import zeek_sources
from romulus.hunt.zeek_sources import (
    key_intents,
    overlap_groups,
    sensor_groups,
    source_groups,
    widened_markers,
    widened_reason,
)
from romulus.sources.compile import build_query
from romulus.sources.models import Predicate, SearchIntent, Window, typed_field_name
from romulus.sources.profile import (
    OPS_BY_TYPE,
    FieldContract,
    FieldSpec,
    contract_from_types,
    native_field,
)
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_links import types_of
from tests.zeek_source_support import matches

ALL_OPS = sorted({op for ops in OPS_BY_TYPE.values() for op in ops})
DNS = next(log for log in ZEEK_LOGS if log.name == 'dns')
CONN = next(log for log in ZEEK_LOGS if log.name == 'conn')
UNTYPED = ('zeek.dns.@proc', 'zeek.conn.@stream', 'zeek.http.some-field', 'zeek.dns.a b', 'zeek.dns.@system')
WINDOW = Window(start=datetime(2024, 11, 18, 14, tzinfo=UTC), end=datetime(2024, 11, 18, 15, tzinfo=UTC))


def _so_types():
    """A Security Onion target's mapping, from its own records, plus the artefact fields."""
    types = {'@timestamp': 'date'}
    for hit in (zf.security_onion(zf.Conn(), 'c'), zl.security_onion(zl.DNS, 'd'), zl.security_onion(zl.HTTP, 'h')):
        types.update(types_of(hit['_source']))
    types.update({name: 'keyword' for name in UNTYPED})
    types['zeek.dns.@system'] = 'text'
    types['zeek.dns.@system.keyword'] = 'keyword'
    return types


def _elastic_types():
    """A Filebeat zeek module target's mapping, plus the artefact fields."""
    types = {'@timestamp': 'date'}
    for hit in (zf.elastic(zf.Conn(), 'c', filebeat=True), zl.elastic(zl.DNS, 'd', filebeat=True),
                zl.elastic(zl.HTTP, 'h', filebeat=True)):
        types.update(types_of(hit['_source']))
    types.update({name: 'keyword' for name in UNTYPED})
    types['zeek.dns.@system'] = 'text'
    types['zeek.dns.@system.keyword'] = 'keyword'
    return types


CONTRACTS = {'security_onion': _so_types, 'elastic_module': _elastic_types}


def test_validator_is_unchanged_and_shared():
    for name in UNTYPED + ('', 'a..b', 'a.', '.a', 'a.b-c', 'a/b', 'a*'):
        assert not typed_field_name(name)
        with pytest.raises(ValueError, match='invalid field name'):
            Predicate(field=name, op='exists')
    for name in ('zeek.dns.query', 'event.dataset', '_path', 'id.orig_h', 'winlog.event_data.ProcessId'):
        assert typed_field_name(name)
        Predicate(field=name, op='exists')
    assert not typed_field_name(None)


@pytest.mark.parametrize('kind', sorted(CONTRACTS))
def test_contract_keeps_untyped_names_visible_and_unsupported_for_every_op(kind):
    types = CONTRACTS[kind]()
    contract = contract_from_types('network', types, role='network')
    for name in UNTYPED + ('zeek.dns.@system.keyword',):
        assert name in contract.fields                    # the source has it: presence stays visible
        assert contract.fields[name].ops == []
        for op in ALL_OPS:
            assert not contract.supports(name, op)
            assert native_field(contract, name, op) is None
            assert zeek_sources.native_field(contract, name, op) is None
            assert zeek_sources.native_field(contract, name + ':ns', op) is None
    # typed names are untouched
    assert contract.supports('event.dataset', 'in') and contract.fields['event.dataset'].aggregatable
    # a stored contract (any build) is classified again when it is loaded
    stored = contract.model_dump()
    stored['fields']['zeek.dns.@proc'] = {'native': 'zeek.dns.@proc', 'natives': ['zeek.dns.@proc'],
                                          'type': 'keyword', 'ops': ['eq', 'missing'], 'aggregatable': True}
    loaded = FieldContract.model_validate(stored)
    assert loaded.fields['zeek.dns.@proc'].ops == [] and not loaded.supports('zeek.dns.@proc', 'missing')


def test_windows_direct_names_are_classified_too():
    types = {'@timestamp': 'date', 'winlog.computer_name': 'keyword', 'winlog.channel': 'keyword',
             'winlog.event_id': 'keyword', 'winlog.provider_name': 'keyword', 'winlog.event_data.Some-Field': 'keyword',
             'winlog.event_data.ProcessId': 'keyword'}
    contract = contract_from_types('win', types)
    assert contract.os_family == 'windows' and contract.linux_fields
    for table in (contract.fields, contract.linux_fields):
        assert table['winlog.event_data.Some-Field'].ops == []
    assert contract.spec('winlog.event_data.Some-Field', os_family='linux').ops == []
    assert contract.supports('process.pid', 'eq')         # an alias over a typed native still works


def test_unclassified_contract_never_puts_a_source_name_in_the_security_onion_bare_group():
    """A source-reported name in `Predicate(field=..., op='missing')` raises ValueError, which would end the hunt.
    A contract built without classification must not reach it either: a source name is never itself a
    predicate."""
    with pytest.raises(ValueError, match="invalid field name: 'zeek.dns.@proc'"):
        Predicate(field='zeek.dns.@proc', op='missing')
    types = _elastic_types()
    raw = FieldContract.model_construct(       # no validation: every mapped name keeps its mapping type's ops
        target='network', role='network', os_family='unknown', time_field='@timestamp', linux_fields={},
        hosts=(), host_inventory_complete=True, zeek_sensor=None, zeek_log=None, nxlog_mixed=False,
        fields={name: FieldSpec(native=name, natives=(name,), type=kind, ops=sorted(OPS_BY_TYPE.get(kind, set())),
                                aggregatable=False) for name, kind in types.items()})
    for log in ZEEK_LOGS:
        for shape in SHAPES:
            for group in source_groups(raw, log, shape):
                assert all(typed_field_name(predicate.field) for predicate in group)
    assert sorted(widened_markers(raw, DNS, SECURITY_ONION)) == [
        'zeek.dns.@proc', 'zeek.dns.@system', 'zeek.dns.@system.keyword', 'zeek.dns.a b']


@pytest.mark.parametrize('kind', sorted(CONTRACTS))
def test_every_zeek_query_builder_completes_and_compiles(kind):
    contract = contract_from_types('network', CONTRACTS[kind](), role='network')
    contracts = {'network': contract}
    for log in ZEEK_LOGS:
        for shape in SHAPES:
            groups = source_groups(contract, log, shape)
            groups += overlap_groups(contract, groups, WINDOW.start, WINDOW.end, shape=shape)
            groups += sensor_groups(contract, log, shape, zl.SENSOR)
            for group in groups:
                assert all(typed_field_name(predicate.field) for predicate in group)
                build_query(SearchIntent(kind='raw', target='network', window=WINDOW, any_of=[group]), contract)
    plan = key_intents(contracts, ZEEK_LOGS, zl.SENSOR, {'zeek.uid'}, ['C1'], WINDOW)
    for intent in plan.intents:
        build_query(intent, contract)
    from romulus.hunt.ics_filters import selection
    selection(contract, {'datasets': {'zeek.modbus': 1, 'zeek.dnp3': 1}})


def test_widened_security_onion_bare_group_is_a_superset_that_raw_reads_keep_exact():
    """The bare group's `zeek.<log>.*` absence markers keep other layouts' rows (a Zeek object, which Security Onion
    never writes) out of it. With `zeek.dns.@proc` the only mapped zeek.dns field, that marker cannot be searched:
    the group is broader, and it selects such a row. Each record's layout is still recognized from the record
    itself, so a raw read never reads it as Security Onion's; a typed marker that can be searched still excludes."""
    types = {'@timestamp': 'date', 'event.module': 'keyword', 'event.dataset': 'keyword', 'event.provider': 'keyword',
             'data_stream.dataset': 'keyword', 'observer.name': 'keyword', 'log.id.uid': 'keyword',
             'zeek.dns.@proc': 'keyword'}
    contract = contract_from_types('network', types, role='network')
    assert widened_markers(contract, DNS, SECURITY_ONION) == ['zeek.dns.@proc']
    bare = source_groups(contract, DNS, SECURITY_ONION)[-1]
    assert [(p.field, p.op) for p in bare] == [('event.module', 'eq'), ('event.provider', 'missing'),
                                               ('event.dataset', 'in')]
    query = build_query(SearchIntent(kind='raw', target='network', window=WINDOW, any_of=[bare]), contract)
    so_row = {'@timestamp': '2024-11-18T14:10:00Z', 'event': {'module': 'zeek', 'dataset': 'dns'},
              'observer': {'name': zl.SENSOR}, 'log': {'id': {'uid': 'C1'}}}
    other = {'@timestamp': '2024-11-18T14:10:00Z', 'event': {'module': 'zeek', 'dataset': 'dns'},
             'zeek': {'dns': {'@proc': 'worker-1'}}}
    assert matches(query, so_row) and zeek_record(so_row).shape == SECURITY_ONION
    assert matches(query, other)                           # the superset
    assert zeek_record(other).shape == AMBIGUOUS           # never read as Security Onion's
    # A searchable marker of the same object still excludes the row at retrieval.
    typed = contract_from_types('network', {**types, 'zeek.dns.query': 'keyword'}, role='network')
    assert widened_markers(typed, DNS, SECURITY_ONION) == ['zeek.dns.@proc']
    bare = source_groups(typed, DNS, SECURITY_ONION)[-1]
    query = build_query(SearchIntent(kind='raw', target='network', window=WINDOW, any_of=[bare]), typed)
    assert not matches(query, {**other, 'zeek': {'dns': {'@proc': 'worker-1', 'query': 'example.test'}}})


def test_other_absence_markers_report_widening_by_mapping_type():
    """A marker the target maps with a type that has no absence search widens the group the same way."""
    types = {'@timestamp': 'date', 'event.module': 'keyword', 'event.dataset': 'keyword', 'event.provider': 'object',
             'fileset.name': 'keyword', 'data_stream.dataset': 'geo_point', 'observer.name': 'keyword',
             'log.id.uid': 'keyword'}
    contract = contract_from_types('network', types, role='network')
    assert widened_markers(contract, DNS, SECURITY_ONION) == ['event.provider']
    assert widened_markers(contract, DNS, ELASTIC) == ['data_stream.dataset']
    assert widened_markers(contract, DNS, PLAIN) == []
    reason = widened_reason('network', DNS, SECURITY_ONION, ['event.provider'])
    assert "'event.provider' cannot be searched as absent" in reason and 'visibility unresolved' in reason


def test_widened_reason_is_bounded_and_quotes_untrusted_names():
    names = [f'zeek.dns.@p{i}' + 'x' * 500 for i in range(5000)] + ['zeek.dns.\nforged line']
    reason = widened_reason('network', DNS, SECURITY_ONION, names)
    assert len(reason) < 600 and 'and 4998 more' in reason and '\n' not in reason
    assert 'not expressible as a typed predicate' in reason


def _so_visibility_hits():
    so_conn = zf.security_onion(replace(zf.Conn(), uid='Cso', ts=zl.T0 + 60), 'so-conn')
    so_dns = zl.security_onion(replace(zl.DNS, ts=zl.T0 + 60), 'so-dns', bare=True)
    so_dns['_source'].pop('data_stream')                  # a 2.3-style bare row: only the bare group selects it
    other = {'_index': 'network', '_id': 'other-dns', '_source': {
        '@timestamp': zl.iso_ms(zl.T0 + 60), 'event': {'module': 'zeek', 'dataset': 'dns'},
        'observer': {'name': zl.SENSOR}, 'zeek': {'dns': {'@proc': 'worker-1'}}}}
    return [so_conn, so_dns, other]


def test_aggregate_visibility_does_not_count_a_widened_group_and_says_why(tmp_path):
    from romulus.config import Settings
    from romulus.hunt.zeek_visibility import VisibilityStore, collect_visibility
    from romulus.site import ZeekPolicy
    from romulus.sources.es import ElasticClient
    from tests.zeek_source_support import ZeekES
    hits = _so_visibility_hits()
    types = {'@timestamp': 'date'}
    for hit in hits:
        types.update(types_of(hit['_source']))
    contract = contract_from_types('network', types, role='network')
    assert widened_markers(contract, DNS, SECURITY_ONION) == ['zeek.dns.@proc']
    assert widened_markers(contract, CONN, SECURITY_ONION) == []
    backend = ZeekES({'network': hits}, {'network': '@timestamp'})
    store = VisibilityStore(tmp_path / 'stage')
    start = datetime.fromtimestamp(zl.T0, UTC)
    window = Window(start=start, end=start + timedelta(minutes=15))
    try:
        collect_visibility(ElasticClient(Settings(home=tmp_path), transport=backend.transport()),
                           {'network': contract}, window, store, ZeekPolicy())
        reasons = [reason for reason in store.reasons if 'zeek.dns.@proc' in reason]
        assert len(reasons) == 1 and 'dns security_onion selection' in reasons[0]
        assert 'not expressible as a typed predicate' in reasons[0] and 'visibility unresolved' in reasons[0]
        counted = dict(store.db.execute('SELECT family, SUM(n) FROM activity GROUP BY family'))
        assert counted == {'net_flow': 1}                 # conn counted; no dns row attributed to any layout
        rows = list(store.visibility(window, 1.0))
        assert rows and all(row['partial'] for row in rows)
    finally:
        store.close()


def _filebeat_hunt(tmp_path, name, *, artefacts):
    from romulus.config import Settings
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.store.db import make_engine, migrate
    from romulus.store.repo import Repo
    from tests.test_zeek_visibility_sweep import DirectProbe
    from tests.zeek_source_support import ZeekES
    hits = [zf.elastic(replace(zf.Conn(), uid='Cfb', ts=zl.T0 + 60), 'fb-conn', filebeat=True),
            zl.elastic(replace(zl.DNS, ts=zl.T0 + 90), 'fb-dns', filebeat=True),
            zl.elastic(replace(zl.HTTP, ts=zl.T0 + 120), 'fb-http', filebeat=True)]
    if artefacts:
        for hit in hits:
            for stream in [key for key, value in hit['_source']['zeek'].items() if isinstance(value, dict)]:
                hit['_source']['zeek'][stream].update({'@proc': 'zeek-worker', '@stream': stream,
                                                       '@system': 'sensor', 'some-field': 'x', 'a b': 'y'})
    types = {'@timestamp': 'date'}
    for hit in hits:
        types.update(types_of(hit['_source']))
    if artefacts:
        types.update({'zeek.conn.@stream': 'keyword', 'zeek.dns.@proc': 'keyword'})
    contract = contract_from_types('network', types, role='network')
    backend = ZeekES({'network': copy.deepcopy(hits)}, {'network': '@timestamp'})
    root = tmp_path / name
    root.mkdir()
    engine = make_engine(root / 'hunt.db')
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt('h', {'targets': ['network']}, 'digest', 'test')
    start = datetime.fromtimestamp(zl.T0, UTC)
    sweep = Sweep(repo, ElasticClient(Settings(home=root), transport=backend.transport()), 'h',
                  Window(start=start, end=start + timedelta(minutes=15)), {'network': contract},
                  stage_dir=root / 'stage')
    sweep.pack = [DirectProbe()]
    sweep._zeek_visibility_enabled = True
    try:
        sweep.run_target('network')
        sweep.finalize()
        audit = repo.latest_audit('h', 'hunt.zeek_visibility')['detail']
        rows = list(repo.zeek_visibility_rows('h', audit['snapshot']['sha256']))
        return contract, audit, rows
    finally:
        sweep.close_stage()
        engine.dispose()


def test_filebeat_hunt_with_artefact_fields_finalizes_with_unchanged_visibility(tmp_path):
    """A Filebeat zeek module index whose rows carry `zeek.dns.@proc` and similar names: the sweep's finalize
    completes, and its visibility is exactly the visibility of the same rows without them."""
    contract, audit, rows = _filebeat_hunt(tmp_path, 'artefacts', artefacts=True)
    assert 'zeek.dns.@proc' in contract.fields and not contract.supports('zeek.dns.@proc', 'missing')
    assert sorted(widened_markers(contract, DNS, SECURITY_ONION)) == [
        'zeek.dns.@proc', 'zeek.dns.@stream', 'zeek.dns.@system', 'zeek.dns.a b', 'zeek.dns.some-field']
    _, plain_audit, plain_rows = _filebeat_hunt(tmp_path, 'plain', artefacts=False)
    assert rows == plain_rows and rows
    assert audit['unresolved'] == plain_audit['unresolved']
    assert audit['snapshot']['sha256'] == plain_audit['snapshot']['sha256']


@pytest.mark.parametrize('scale', [1, 4])
def test_classification_is_one_check_per_name_at_mission_scale(monkeypatch, scale):
    from romulus.sources import profile
    calls = []
    original = profile.typed_field_name

    def counted(name):
        calls.append(name)
        return original(name)
    monkeypatch.setattr(profile, 'typed_field_name', counted)
    n = 25_000 * scale
    types = {'@timestamp': 'date', 'event.module': 'keyword', 'event.dataset': 'keyword'}
    for i in range(n):
        types[f'zeek.dns.f{i}'] = 'keyword'
        types[f'zeek.dns.@p{i}'] = 'keyword'
        types[f'zeek.http.f-{i}'] = 'long'
        types[f'zeek.conn.a b{i}'] = 'object'                # no ops at all: never checked
    contract = contract_from_types('network', types, role='network')
    assert len(calls) == 3 * n + 3                         # one check per name that has an op, and no more
    unsupported = {name for name, spec in contract.fields.items() if not spec.ops}
    assert len(unsupported) == 3 * n + 1 and '@timestamp' in unsupported
    assert contract.fields['@timestamp'].aggregatable      # aggregation by code-named fields is unchanged
    assert all(contract.supports(f'zeek.dns.f{i}', 'missing') for i in range(n))
    calls.clear()
    FieldContract.model_validate(contract.model_dump())
    assert len(calls) == n + 2                             # a loaded contract: only names that still have ops


def test_security_onion_groups_over_a_large_contract_stay_typed():
    types = {'@timestamp': 'date', 'event.module': 'keyword', 'event.dataset': 'keyword', 'observer.name': 'keyword',
             'log.id.uid': 'keyword'}
    for i in range(2000):
        types[f'zeek.dns.f{i}'] = 'keyword'
        types[f'zeek.dns.@p{i}'] = 'keyword'
    contract = contract_from_types('network', types, role='network')
    groups = source_groups(contract, DNS, SECURITY_ONION)
    assert all(typed_field_name(predicate.field) for group in groups for predicate in group)
    assert sum(predicate.op == 'missing' for predicate in groups[-1]) == 2000
    widened = widened_markers(contract, DNS, SECURITY_ONION)
    assert len(widened) == 2000
    assert len(widened_reason('network', DNS, SECURITY_ONION, widened)) < 400
