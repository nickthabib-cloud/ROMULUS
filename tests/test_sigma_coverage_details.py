"""Imported-rule coverage bounds detail without changing retrieval scope."""
import json

import pytest

from romulus.content.sigma_coverage import (
    bounded_details,
    coverage_view,
    positive_event_ids,
    reason_signature,
)
from romulus.content.sigma_parser import parse_rule
from romulus.detect.sigma import SigmaRule
from romulus.hunt.sweep import Sweep
from tests.test_sigma_playbook import row


def test_sigma_cell_retains_bounded_reasons_and_exact_summary_counts():
    owner = SigmaRule(row())
    sweep = object.__new__(Sweep)
    reasons = [str(number)+': '+('long reason '*100) for number in range(100)]
    cell = sweep._cell(owner, 'target', 'partition', 'evaluated_partial', detail={'reasons': reasons})
    assert len(cell['detail']['reasons']) <= 9
    assert max(map(len, cell['detail']['reasons'])) <= 256
    assert cell['detail']['reason_total'] == 100
    assert cell['detail']['reason_omitted'] == 92
    assert cell['detail']['reason_truncated'] == 100


def test_reason_summary_is_idempotent_and_does_not_change_static_rule_detail():
    from romulus.detect.base import Playbook
    original = {'reasons': ['long '*100]*100}
    bounded = bounded_details(original)
    assert bounded_details(bounded) == bounded
    assert len(json.dumps(bounded)) < 3000
    assert original['reasons'] == ['long '*100]*100
    static = Playbook()
    static.id, static.version = 'static.rule', '1'
    assert object.__new__(Sweep)._cell(static, 'target', 'p', 'evaluated_partial', detail=original)['detail'] == original


def metadata(detection, *, number='service', category=None):
    logsource = {'product': 'windows', 'category': category} if category else {'product': 'windows', 'service': 'sysmon'}
    parsed = parse_rule({'title': 'Synthetic native-class coverage', 'logsource': logsource, 'detection': detection})
    assert not parsed['reasons']
    return dict(row(), id=number, ast=parsed['ast'], mapping=parsed['mapping'])


@pytest.mark.parametrize('detection,expected', [
    ({'selection': {'EventID': 1}, 'condition': 'selection'}, {'1'}),
    ({'selection': {'EventID': [1, '3']}, 'condition': 'selection'}, {'1', '3'}),
    ({'selection': {'EventID': [1, 3]}, 'filter': {'EventID': 3},
      'condition': 'selection and not filter'}, {'1', '3'}),
    ({'selection': {'Image': 'evil.exe'}, 'filter': {'EventID': 1},
      'condition': 'selection and not filter'}, None),
    ({'one': {'EventID': 1}, 'two': {'EventID': 3}, 'condition': 'one or two'}, {'1', '3'}),
    ({'one': {'EventID': 1}, 'two': {'Image': 'evil.exe'}, 'condition': 'one or two'}, None),
    ({'one': {'EventID': [1, 3]}, 'two': {'EventID': [3, 5]}, 'condition': 'one and two'}, {'3'}),
    ({'selection': {'EventID|contains': '1'}, 'condition': 'selection'}, None),
    ({'selection': {'EventID|gt': 1}, 'condition': 'selection'}, None),
    ({'selection': {'EventID|exists': True}, 'condition': 'selection'}, None),
    ({'selection': {'EventID': '4*'}, 'condition': 'selection'}, None),
])
def test_only_positive_finite_eventid_constraints_narrow_collection_reasons(detection, expected):
    assert positive_event_ids(metadata(detection)['ast']) == (None if expected is None else frozenset(expected))


def test_reason_view_and_cache_signature_preserve_runtime_classes_and_include_os_scope():
    owner = SigmaRule(metadata({'selection': {'EventID': 1}, 'condition': 'selection'}))
    original = owner.windows_event_classes
    view = coverage_view(owner)
    assert len(original) > 1 and {item[2] for item in view.windows_event_classes} == {1}
    assert owner.windows_event_classes == original and owner._classes == SigmaRule(owner.metadata)._classes
    view.os_families = ('linux',)
    assert reason_signature(view) != reason_signature(coverage_view(owner))


def run_rules(tmp_path, monkeypatch, owners, reason_hook, *, raws=None):
    from romulus.config import Settings
    from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
    from romulus.hunt import sweep as module
    from romulus.sources.es import ElasticClient
    from tests.test_sweep import _repo
    from tests.test_windows_rpc_retrieval import TARGET, WINDOW, contract
    from tests.throughput_fixture import MiniES
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
    monkeypatch.setattr(module, 'fresh_pack', lambda: owners)
    if raws is None:
        raw = windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, 1, 'ws01.example.test', 1,
            WINDOW.start.isoformat(), {'Image': r'C:\Tools\benign.exe'}), 'elastic_agent')
        raw['_index'] = TARGET
        raws = [raw]
    es = MiniES({TARGET: raws}, {TARGET: '@timestamp'})
    client = ElasticClient(Settings(es_url='http://es.invalid'), transport=es.transport())
    repo = _repo()
    instance = Sweep(repo, client, 'h1', WINDOW, {TARGET: contract()}, stage_dir=tmp_path)
    monkeypatch.setattr(instance, '_windows_rule_reasons', lambda _target, _contract, proxy, *_args: reason_hook(proxy))
    instance.run_target(TARGET)
    return instance, repo


def test_real_sweep_bounds_each_shared_signature_cell_and_does_not_share_os_scope(tmp_path, monkeypatch):
    windows = SigmaRule(row())
    linux_metadata = row(1)
    linux_metadata['mapping'] = dict(linux_metadata['mapping'], os_families=['linux'])
    linux = SigmaRule(linux_metadata)
    copy = SigmaRule(row(2))
    calls = []
    def reasons(proxy):
        calls.append(proxy.os_families)
        return [str(number)+': '+('native reason '*100) for number in range(100)] if 'windows' in proxy.os_families else []
    instance, repo = run_rules(tmp_path, monkeypatch, [windows, linux, copy], reasons)
    try:
        assert calls == [('windows',), ('linux',)]
        cells = repo.rule_cells('h1')
        for owner in [windows, copy]:
            [cell] = [cell for cell in cells if cell['rule_id'] == owner.id]
            detail = cell['detail']
            assert detail['reason_total'] == 100
            assert detail['reason_omitted'] == 92 and detail['reason_truncated'] == 100
            assert len(detail['reasons']) == 9 and max(map(len, detail['reasons'])) <= 256
            assert len(json.dumps(detail)) < 3000
        [linux_cell] = [cell for cell in cells if cell['rule_id'] == linux.id]
        assert linux_cell['detail']['reasons'] == []
        assert not instance.failed_rules
    finally:
        instance.close_stage()
        repo.engine.dispose()


def test_service_eventid_narrows_reason_scope_while_other_native_records_still_reach_rule(tmp_path, monkeypatch):
    from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL
    from tests.test_windows_rpc_retrieval import TARGET, WINDOW
    from tests.windows_fixtures import LogicalWindowsEvent, windows_hit
    owner = SigmaRule(metadata({'selection': {'EventID': 1, 'Image|endswith': '\\evil.exe'}, 'condition': 'selection'}))
    original = owner.windows_event_classes
    raws = []
    for number, code in enumerate([1, 3], 1):
        raw = windows_hit(LogicalWindowsEvent(SYSMON_CHANNEL, SYSMON, code, 'ws01.example.test', number,
            WINDOW.start.isoformat(), {'Image': r'C:\Tools\evil.exe'}), 'elastic_agent')
        raw['_index'] = TARGET
        raws.append(raw)
    calls = []
    instance, repo = run_rules(tmp_path, monkeypatch, [owner],
        lambda proxy: calls.append(proxy.windows_event_classes) or [], raws=raws)
    try:
        assert {item[2] for item in calls[0]} == {1}
        assert owner.windows_event_classes == original
        assert owner.match_evaluations == 2
        assert len(repo.candidates('h1')) == 1
        assert not instance.failed_rules
    finally:
        instance.close_stage()
        repo.engine.dispose()


def test_real_sweep_marks_unknown_comparison_partial_and_names_field(tmp_path, monkeypatch):
    owner = SigmaRule(metadata({'selection': {'OriginalFileName': 'evil.exe'}, 'condition': 'selection'},
                               category='process_creation'))
    instance, repo = run_rules(tmp_path, monkeypatch, [owner], lambda _proxy: [])
    try:
        [cell] = repo.rule_cells('h1')
        assert cell['state'] == 'evaluated_partial'
        assert cell['detail']['undecidable_comparisons'] == 1
        assert 'missing_typed_value: process.original_file_name' in ' '.join(cell['detail']['reasons'])
        assert not repo.candidates('h1') and not instance.failed_rules
    finally:
        instance.close_stage()
        repo.engine.dispose()


def test_publication_overflow_marks_its_partition_partial_and_names_withheld_positives(tmp_path, monkeypatch):
    owner = SigmaRule(metadata({'selection': {'EventID': 1}, 'condition': 'selection'}, category='process_creation'))
    owner.PUBLICATION_LIMIT = 0
    instance, repo = run_rules(tmp_path, monkeypatch, [owner], lambda _proxy: [])
    try:
        [cell] = repo.rule_cells('h1')
        assert cell['state'] == 'match_on_partial'
        assert '1 matching record(s)' in ' '.join(cell['detail']['reasons'])
        assert len(repo.candidates('h1')) == 1
    finally:
        instance.close_stage()
        repo.engine.dispose()


def test_mapping_exclusions_are_named_on_cells(tmp_path, monkeypatch):
    owner = SigmaRule(metadata({'selection': {'Image|endswith': '\\evil.exe'}, 'condition': 'selection'},
                               category='network_connection'))
    instance, repo = run_rules(tmp_path, monkeypatch, [owner], lambda _proxy: [])
    try:
        [cell] = repo.rule_cells('h1')
        reasons = ' '.join(cell['detail']['reasons'])
        assert 'Sigma mapping exclusion:' in reasons and '5156' in reasons
        assert 'not evaluated' in reasons
    finally:
        instance.close_stage()
        repo.engine.dispose()


def test_script_finalize_batches_publish_one_cited_sigma_group_and_bounded_coverage(tmp_path, monkeypatch):
    from datetime import timedelta

    from romulus.evidence.typed import RawRef, fv
    from romulus.evidence.windows_catalog import POWERSHELL_CHANNEL, POWERSHELL_PROVIDER
    from romulus.evidence.windows_reassembly import ScriptBlockAssembler
    from romulus.hunt import sweep as module
    from romulus.sources.models import Window
    from tests.test_sweep import _repo
    from tests.test_windows_reassembly import NOW, _part
    owner = SigmaRule(metadata({'selection': {'ScriptBlockText|contains': 'evil'},
        'path': {'Path': 'x.ps1'}, 'condition': 'selection or path'},
                               category='ps_script'))
    monkeypatch.setattr(module, 'fresh_pack', lambda: [owner])
    repo = _repo()
    instance = Sweep(repo, None, 'h1', Window(start=NOW, end=NOW+timedelta(hours=1)), {}, stage_dir=tmp_path)
    assembler = ScriptBlockAssembler(tmp_path/'scripts', budget=instance.budget)
    instance._windows_scripts = assembler
    events = []
    for number in range(130):
        event = _part(1, 2, 'evil', native='part-'+str(number), block='block-'+str(number).zfill(3))
        event.fields['event.channel'] = fv(POWERSHELL_CHANNEL, 'native:channel')
        event.fields['event.provider'] = fv(POWERSHELL_PROVIDER, 'native:provider')
        if number >= 128:
            event.fields['script.path'] = fv('x.ps1', 'native:path')
        event.raw = [RawRef(target='windows', native_id='part-'+str(number))]
        events.append(event)
    sources = {ref.key: {'serial': event.id} for event in events for ref in event.raw}
    try:
        list(assembler.consume(events, sources))
        instance._finalize_windows_script_blocks()
        [candidate] = repo.candidates('h1')
        assert candidate['gate_results']['aggregate_summary']['count'] == 130
        assert candidate['gate_results']['_revision']['count'] == 1
        assert not candidate['gate_results'].get('_citation_unavailable')
        [cell] = repo.rule_cells('h1')
        assert cell['state'] == 'match_on_partial' and cell['matched'] == 2
        assert cell['detail']['undecidable_comparisons'] == 128
        assert 'missing_typed_value: script.path' in ' '.join(cell['detail']['reasons'])
        assert len(cell['detail']['reasons']) <= 9
        assert not instance.failed_rules
    finally:
        instance.close_stage()
        repo.engine.dispose()
