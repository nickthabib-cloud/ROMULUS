"""Synthetic native timestamp alternatives from the public EVTX renderer and eCAR schemas.

https://github.com/omerbenamram/evtx
https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md
"""
from copy import deepcopy

import pytest

from romulus.errors import SourceError
from romulus.sources.profile import build_profile
from tests.test_host_shapes_profile import ProfileClient


class TimeClient(ProfileClient):
    def __init__(self, *, flat=False, count=1, failure=False):
        super().__init__(flat=flat, dynamic=False)
        self.count, self.failure = count, failure

    def search(self, target, body):
        query = body.get('query', {}).get('bool', {})
        if query.get('must_not') == [{'exists': {'field': '@timestamp'}}]:
            if self.failure:
                raise SourceError('synthetic temporal count failure')
            return {'hits': {'total': {'value': self.count, 'relation': 'eq'}}}
        return super().search(target, body)


@pytest.mark.parametrize('flat', [False, True])
@pytest.mark.parametrize('failure', [False, True])
def test_optional_pipeline_timestamp_has_visible_omission_count_or_unknown(flat, failure):
    profile, current = build_profile(TimeClient(flat=flat, failure=failure), 'raw')
    [gap] = profile.model_dump()['temporal_gaps']
    assert gap['records'] == (None if failure else 1)
    assert gap['primary'] == '@timestamp' and gap['alternate'].endswith('SystemTime')
    assert 'whole index' in gap['count_scope'] and 'hunt-window membership unverified' in gap['reason']
    assert current.temporal_gaps == (gap['reason'],)
    assert gap['reason'] in profile.notes


def test_zero_temporal_count_adds_no_new_profile_or_contract_field():
    profile, current = build_profile(TimeClient(count=0), 'raw')
    assert 'temporal_gaps' not in profile.model_dump() and 'temporal_gaps' not in current.model_dump()


def test_temporal_gap_propagates_to_sweep_and_actual_link_coverage(tmp_path):
    from datetime import timedelta

    from romulus.config import Settings
    from romulus.detect.windows_proxy import CertutilDownloadDecode
    from romulus.evidence.windows import normalize_windows
    from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
    from romulus.hunt.pivot import PivotExecutor
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from tests.test_host_shapes_profile import WINDOW
    from tests.test_mixed_host_shapes import _mixed_documents
    from tests.test_sweep import _repo
    from tests.throughput_fixture import MiniES

    profile, current = build_profile(TimeClient(), 'raw')
    rows = [_mixed_documents()[0]]
    missing = deepcopy(rows[0])
    missing['_id'] = 'missing-pipeline'
    missing['_source'].pop('@timestamp')
    # The profile count covers this omitted row; the backend below serves the primary-time searchable subset.
    assert normalize_windows(missing).ts == normalize_windows(rows[0]).ts
    client = ElasticClient(Settings(es_url='http://es.invalid'),
                           transport=MiniES({'raw': rows}, {'raw': '@timestamp'}).transport())
    repo = _repo()
    runner = Sweep(repo, client, 'h1', WINDOW, {'raw': current}, stage_dir=tmp_path / 'sweep')
    runner.pack = [CertutilDownloadDecode()]
    runner._profiles = {'raw': profile.model_dump()}
    try:
        runner.run_target('raw')
        runner.finalize()
        assert any('temporal coverage unresolved' in reason for reason in runner.partial_reasons)
        assert any('temporal coverage unresolved' in str(cell['detail']) for cell in repo.rule_cells('h1'))
        root = normalize_windows(rows[0])
        anchor = LinkAnchor(finding_id='root', ts=root.ts, host=root.host, event_ids=[root.id], events=[root])
        executor = PivotExecutor(repo, client, 'h1', {'raw': current}, stage_dir=tmp_path / 'pivot')
        result = LinkFetcher(executor, WINDOW.start, WINDOW.end).fetch(anchor, 'host_after_anchor',
            LinkWindow(label='anchor +5 min', start=root.ts, end=root.ts+timedelta(minutes=5)))
        assert result.status == 'partial' and any('temporal coverage unresolved' in reason for reason in result.reasons)
        assert result.coverage and all(cell.unresolved_ranges for cell in result.coverage)
    finally:
        runner.close_stage()
        repo.engine.dispose()


def test_temporal_gap_with_no_selected_partitions_still_has_unresolved_cells(tmp_path, monkeypatch):
    from romulus.detect.windows_proxy import CertutilDownloadDecode
    from romulus.hunt import sweep as module
    from tests.test_host_shapes_profile import WINDOW
    from tests.test_sweep import _repo

    profile, current = build_profile(TimeClient(), 'raw')
    repo = _repo()
    runner = module.Sweep(repo, None, 'h1', WINDOW, {'raw': current}, stage_dir=tmp_path)
    runner.pack = [CertutilDownloadDecode()]
    runner._profiles = {'raw': profile.model_dump()}
    monkeypatch.setattr(runner, '_prepare_windows_inventory', lambda *_: None)
    monkeypatch.setattr(module, 'plan_partitions', lambda *_: [])
    try:
        runner.run_target('raw')
        runner.finalize()
        assert runner.stats['records'] == 0
        assert any('temporal coverage unresolved' in reason for reason in runner.partial_reasons)
        cells = repo.rule_cells('h1')
        assert any(cell['state'] == 'evaluated_partial' and 'temporal coverage unresolved' in str(cell['detail'])
                   for cell in cells)
    finally:
        runner.close_stage()
        repo.engine.dispose()
