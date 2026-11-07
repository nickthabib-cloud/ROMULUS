"""Carved HTTP bodies use pinned indicators with bounded retained witnesses."""
import hashlib
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from romulus.config import Settings
from romulus.content.indicator_import import ImportedIndicator
from romulus.content.indicator_lists import IndicatorLists
from romulus.detect import indicators
from romulus.hunt import packets as hp
from romulus.report import manifest as rm
from romulus.sources import packets as pk
from romulus.sources.models import Completeness, SearchOutcome, Window
from romulus.store import schema as t
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.test_packets import T0, TARGET, _contract, _Packets, _row, _session

BODY = b'MZ'+b'\x00'*60+b'PE\x00\x00'+b'\x90'*200
URL = 'http://192.0.2.174/update.exe'
SHA256 = hashlib.sha256(BODY).hexdigest()
RULE = 'ioc.indicator_match'


def repository(rows):
    engine = make_engine(':memory:')
    migrate(engine)
    repo = Repo(engine)
    lists = IndicatorLists(repo)
    meta = lists.create_version(rows, name='Partner packet indicators', source='Partner', author='analyst',
        now=T0-timedelta(days=1), expires_at=T0+timedelta(days=30)) if rows else None
    repo.create_hunt('h1', {'indicator_lists': lists.pin(T0)}, 'digest', 'test')
    return repo, lists, meta


def stage(tmp_path, monkeypatch, repo, rows):
    sessions = [_session('241118-BODY00000001', 50001)]
    def execute(client, intent, contract):
        return SearchOutcome(target=intent.target, fingerprint='fixture', started_at=T0, ended_at=T0,
            completeness=Completeness.complete, total=len(sessions) if intent.kind == 'raw' else 0,
            total_relation='eq', returned=len(sessions) if intent.kind == 'raw' else 0,
            records=sessions if intent.kind == 'raw' else [])
    monkeypatch.setattr(hp, 'execute', execute)
    monkeypatch.setattr(hp, 'run_tshark', lambda *args, **kwargs: pk.TsharkResult(rows=rows))
    return hp.run_packet_stage(Settings(home=tmp_path), repo, None, 'h1',
        Window(start=T0-timedelta(hours=1), end=T0+timedelta(hours=1)),
        {TARGET: _contract()}, packets=_Packets())


def response(body=BODY, url=URL, offset=0):
    row = _row(50001, T0.timestamp()+offset, body=body, uri=url)
    row['http.content_type'] = ['application/x-dosexec' if body.startswith(b'MZ') else 'text/plain']
    return row


def test_packet_body_hash_and_absolute_url_match_pinned_lists_with_retained_citations(tmp_path, monkeypatch):
    repo, _lists, _meta = repository([ImportedIndicator('sha256', SHA256), ImportedIndicator('url', URL)])
    try:
        summary = stage(tmp_path, monkeypatch, repo, [response()])
        found = [row for row in repo.candidates('h1') if row['rule_id'] == RULE]
        assert len(found) == 2
        assert any('response body with SHA-256' in row['claim'] for row in found)
        assert any('HTTP request target URL' in row['claim'] for row in found)
        assert all('version 1' in row['claim'] for row in found)
        assert all(cite['status'] == 'retained' for row in found for cite in rm._citations(repo, row))
        assert summary['matched'] == 2 and summary['responses'] == 1
        cells = [cell for cell in repo.rule_cells('h1') if cell['rule_id'] == RULE]
        assert len(cells) == 1
        assert cells[0]['target'] == f'arkime-pcap:{TARGET}' and cells[0]['state'] == 'matched'
        assert 'only' in cells[0]['detail']['selection'].lower()
        assert all(word in cells[0]['detail']['selection'] for word in ('text', 'script', 'executable'))
    finally:
        repo.engine.dispose()


def test_unmatched_packet_bodies_are_not_retained(tmp_path, monkeypatch):
    repo, _lists, _meta = repository([ImportedIndicator('sha256', SHA256)])
    try:
        stage(tmp_path, monkeypatch, repo, [response(), response(b'ordinary prose', offset=1),
                                           response(b'another document', offset=2)])
        with repo.engine.connect() as connection:
            assert connection.scalar(select(func.count()).select_from(t.typed_event)) == 1
            assert connection.scalar(select(func.count()).select_from(t.raw_record)) == 1
        [finding] = [row for row in repo.candidates('h1') if row['rule_id'] == RULE]
        [event] = repo.events_by_ids(finding['event_ids'])
        assert event['event']['fields']['file.sha256']['value'] == SHA256
    finally:
        repo.engine.dispose()


def test_packet_resume_keeps_the_original_indicator_pin_after_a_list_edit(tmp_path, monkeypatch):
    repo, lists, meta = repository([ImportedIndicator('sha256', SHA256)])
    try:
        lists.create_version([ImportedIndicator('sha256', 'ab'*32)], list_id=meta['id'],
            name='Partner packet indicators', source='Partner', author='analyst', now=T0)
        stage(tmp_path, monkeypatch, repo, [response()])
        original = [row for row in repo.candidates('h1') if row['rule_id'] == RULE]
        assert len(original) == 1 and 'version 1' in original[0]['claim']
        stage(tmp_path, monkeypatch, repo, [response()])
        resumed = [row for row in repo.candidates('h1') if row['rule_id'] == RULE]
        assert [row['id'] for row in resumed] == [row['id'] for row in original]
        assert resumed[0]['claim'] == original[0]['claim']
    finally:
        repo.engine.dispose()


def test_packet_coverage_counts_only_kinds_delivered_bodies_can_carry(tmp_path, monkeypatch):
    repo, _lists, _meta = repository([ImportedIndicator('md5', 'ab'*16), ImportedIndicator('url', URL+'/other')])
    try:
        stage(tmp_path, monkeypatch, repo, [response(), response(offset=1)])
        cells = [cell for cell in repo.rule_cells('h1') if cell['rule_id'] == RULE]
        assert len(cells) == 1
        assert cells[0]['evaluated'] == 2 and cells[0]['matched'] == 0
        assert not any('md5 cannot be searched' in reason for reason in cells[0]['detail']['reasons'])
        assert cells[0]['state'] == 'positive_only'
    finally:
        repo.engine.dispose()


def test_packet_stage_uses_shipped_indicators_without_a_local_overlay(tmp_path, monkeypatch):
    shipped = indicators.Indicator('shipped.address', 'ip', ('192.0.2.174',),
                                   'Listed server', 'high', 'high')
    monkeypatch.setattr(indicators, '_SET', indicators.IndicatorSet([shipped], 'fixture'))
    repo, _lists, _meta = repository([])
    try:
        stage(tmp_path, monkeypatch, repo, [response()])
        found = [row for row in repo.candidates('h1') if row['rule_id'] == RULE]
        assert len(found) == 1 and 'source address 192.0.2.174' in found[0]['claim']
        assert found[0]['lane'] == 'high'
        assert not [cell for cell in repo.rule_cells('h1') if cell['rule_id'] == RULE]
    finally:
        repo.engine.dispose()


@pytest.mark.parametrize('kind,value', [
    ('ip', '192.0.2.174'), ('md5', 'ab'*16), ('sha1', 'ab'*20),
    ('domain', 'example.test'), ('program_name', 'payload.exe'),
])
def test_packet_indicator_cell_requires_a_pinned_body_kind(tmp_path, monkeypatch, kind, value):
    repo, _lists, _meta = repository([ImportedIndicator(kind, value)])
    try:
        stage(tmp_path, monkeypatch, repo, [response()])
        assert not [cell for cell in repo.rule_cells('h1') if cell['rule_id'] == RULE]
        if kind == 'ip':
            assert any(row['rule_id'] == RULE for row in repo.candidates('h1'))
    finally:
        repo.engine.dispose()


def test_packet_indicator_cell_does_not_inherit_another_rules_limit(tmp_path, monkeypatch):
    from romulus.detect.base import Playbook

    class LimitedBodyRule(Playbook):
        id = 'fixture.body_limit'
        version = '1'
        families = ('http_body',)
        def consume(self, events):
            self.evaluated += len(events)
            self.note_limit('fixture', 'Only the earlier rule reached its state budget')
        def finalize(self):
            return []

    monkeypatch.setattr(hp, 'PACKET_PLAYBOOKS', [LimitedBodyRule])
    repo, _lists, _meta = repository([ImportedIndicator('sha256', SHA256)])
    try:
        summary = stage(tmp_path, monkeypatch, repo, [response()])
        [cell] = [cell for cell in repo.rule_cells('h1') if cell['rule_id'] == RULE]
        assert cell['state'] == 'matched'
        assert not any('earlier rule' in reason for reason in cell['detail']['reasons'])
        assert any('earlier rule' in reason for reason in summary['partial_reasons'])
    finally:
        repo.engine.dispose()


@pytest.mark.parametrize('pinned_body_kind', [False, True])
def test_packet_matching_keeps_shipped_body_indicators_with_optional_pinned_lists(
        tmp_path, monkeypatch, pinned_body_kind):
    shipped = indicators.Indicator('shipped.body', 'sha256', (SHA256,),
                                   'Listed body', 'high', 'high')
    monkeypatch.setattr(indicators, '_SET', indicators.IndicatorSet([shipped], 'fixture'))
    rows = [ImportedIndicator('url', URL)] if pinned_body_kind else []
    repo, _lists, _meta = repository(rows)
    try:
        stage(tmp_path, monkeypatch, repo, [response()])
        found = [row for row in repo.candidates('h1') if row['rule_id'] == RULE]
        assert len(found) == 1 + int(pinned_body_kind)
        assert any('response body with SHA-256' in row['claim'] for row in found)
        cells = [cell for cell in repo.rule_cells('h1') if cell['rule_id'] == RULE]
        assert len(cells) == int(pinned_body_kind)
        if pinned_body_kind:
            assert any('HTTP request target URL' in row['claim'] for row in found)
    finally:
        repo.engine.dispose()


def test_packet_indicator_groups_spill_and_reload_without_a_body_lifetime_map(tmp_path, monkeypatch):
    urls = [f'http://192.0.2.174/payload/{index}.exe' for index in range(600)]
    repo, _lists, _meta = repository([ImportedIndicator('url', url) for url in urls])
    observed = {'batches': [], 'spill_rows': 0, 'raws': None, 'closed': False}
    class SmallHotIndicator(indicators.IndicatorMatch):
        HOT = 2
        def finalize(self):
            observed['spill_rows'] = self.groups.on_disk
            return super().finalize()
        def close_spill(self):
            super().close_spill()
            observed['closed'] = self._spill is None
    original_save = repo.save_evidence
    def save(hunt_id, events, raw_sources, task_id, **kwargs):
        values = list(events)
        observed['batches'].append((len(values), len(raw_sources)))
        return original_save(hunt_id, values, raw_sources, task_id, **kwargs)
    original_close = hp._Target.close
    def close(run):
        observed['raws'] = len(run.raw_sources)
        return original_close(run)
    monkeypatch.setattr(hp, 'IndicatorMatch', SmallHotIndicator)
    monkeypatch.setattr(hp._Target, 'close', close)
    monkeypatch.setattr(repo, 'save_evidence', save)
    try:
        summary = stage(tmp_path, monkeypatch, repo, [response(url=url, offset=index)
                                                    for index, url in enumerate(urls)])
        found = [row for row in repo.candidates('h1') if row['rule_id'] == RULE]
        assert len(found) == len(urls) and summary['matched'] == len(urls)
        assert observed['spill_rows'] > 0 and observed['closed']
        assert observed['raws'] == 0
        assert max(size for size, _raws in observed['batches']) <= hp.BODY_EVENT_BATCH
        assert max(raws for _size, raws in observed['batches']) <= hp.BODY_EVENT_BATCH
        with repo.engine.connect() as connection:
            assert connection.scalar(select(func.count()).select_from(t.typed_event)) == len(urls)
        assert all(cite['status'] == 'retained' for row in (found[0], found[-1])
                   for cite in rm._citations(repo, row))
    finally:
        repo.engine.dispose()


def test_packet_indicator_state_is_closed_when_publication_fails(tmp_path, monkeypatch):
    repo, _lists, _meta = repository([ImportedIndicator('sha256', SHA256)])
    closed = []
    class WatchedIndicator(indicators.IndicatorMatch):
        def release_state(self):
            closed.append('released')
            super().release_state()
        def close_spill(self):
            closed.append('closed')
            super().close_spill()
    def fail(*_args, **_kwargs):
        raise RuntimeError('publication interrupted')
    monkeypatch.setattr(hp, 'IndicatorMatch', WatchedIndicator)
    monkeypatch.setattr(hp, 'publish_match', fail)
    try:
        with pytest.raises(RuntimeError, match='publication interrupted'):
            stage(tmp_path, monkeypatch, repo, [response()])
        assert closed == ['released', 'closed']
        assert not list((tmp_path/'stage').glob('romulus-pcap-*'))
    finally:
        repo.engine.dispose()


def test_shipped_only_packet_indicators_use_the_streaming_group_finalizer(tmp_path, monkeypatch):
    shipped = indicators.Indicator('shipped.address', 'ip', ('192.0.2.174',),
                                   'Listed server', 'high', 'high')
    monkeypatch.setattr(indicators, '_SET', indicators.IndicatorSet([shipped], 'fixture'))
    class StreamingIndicator(indicators.IndicatorMatch):
        def finalize(self):
            raise AssertionError('shipped-only packet groups must not be materialized as a list')
    monkeypatch.setattr(hp, 'IndicatorMatch', StreamingIndicator)
    repo, _lists, _meta = repository([])
    try:
        summary = stage(tmp_path, monkeypatch, repo, [response()])
        assert summary['matched'] == 1
        assert len([row for row in repo.candidates('h1') if row['rule_id'] == RULE]) == 1
    finally:
        repo.engine.dispose()
