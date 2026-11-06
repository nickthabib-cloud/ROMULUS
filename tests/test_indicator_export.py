"""List-version exports preserve normalized values and attribution offline."""
import csv
import io

import yaml

from romulus.content.indicator_import import ImportedIndicator, parse_indicator_file
from romulus.content.indicator_lists import IndicatorLists
from romulus.detect.indicators import load_indicators
from tests.test_sweep import _repo


def test_csv_export_roundtrips_the_selected_version(tmp_path):
    from romulus.content.indicator_export import export_indicators
    repo = _repo()
    store = IndicatorLists(repo)
    try:
        first = store.create_version([ImportedIndicator('sha256', 'ab'*32, 'A, "quoted" label', ('T1059',))],
            name='Mission', source='Partner CSV', author='analyst')
        store.create_version([ImportedIndicator('ip', '192.0.2.1')], list_id=first['id'],
            name='Mission', source='Partner CSV', author='analyst')
        text = ''.join(export_indicators(store, first['id'], 1, 'csv'))
        assert list(csv.DictReader(io.StringIO(text))) == [{
            'kind': 'sha256', 'value': 'ab'*32, 'label': 'A, "quoted" label', 'attack': 'T1059'}]
        path = tmp_path/'roundtrip.csv'
        path.write_text(text, encoding='utf-8')
        parsed = parse_indicator_file(path)
        [row] = list(parsed.rows)
        assert row.kind == 'sha256' and row.value == 'ab'*32
        assert row.label == 'A, "quoted" label' and row.attack == ('T1059',)
    finally:
        repo.engine.dispose()


def test_rulepack_export_uses_existing_schema_and_retains_provenance(tmp_path):
    from romulus.content.indicator_export import export_indicators
    repo = _repo()
    store = IndicatorLists(repo)
    try:
        meta = store.create_version([ImportedIndicator('x509_sha1', 'cd'*20)],
            name='Certificates', source='Offline mission file', author='analyst')
        text = ''.join(export_indicators(store, meta['id']))
        doc = yaml.safe_load(text)
        assert doc['schema_version'] == 1
        assert doc['provenance']['source'] == 'Offline mission file'
        assert doc['provenance']['author'] == 'analyst'
        assert doc['provenance']['version'] == 1 and doc['provenance']['digest'] == meta['digest']
        path = tmp_path/'list.yaml'
        path.write_text(text, encoding='utf-8')
        [indicator] = load_indicators(tmp_path).indicators
        assert indicator.kind == 'x509_sha1' and indicator.values == ('cd'*20,)
    finally:
        repo.engine.dispose()
