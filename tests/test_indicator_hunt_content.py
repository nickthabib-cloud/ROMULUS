"""Real hunt creation freezes the local list set, and fresh sweeps use that pin."""
from datetime import UTC, datetime, timedelta

from romulus.config import Settings
from romulus.content.indicator_import import ImportedIndicator
from romulus.content.indicator_lists import IndicatorLists
from romulus.hunt import run as hunt_run
from romulus.hunt.sweep import Sweep
from romulus.sources.models import Window
from romulus.sources.profile import SourceProfile
from tests.test_indicators import net_event


def create_local_hunt(tmp_path, monkeypatch, store_rows):
    settings = Settings(home=tmp_path, es_index_patterns=['idx'])
    repo = hunt_run.open_repo(settings)
    lists = IndicatorLists(repo)
    now = datetime.now(UTC)
    meta = lists.create_version(store_rows, name='Pinned list', source='Partner', author='analyst',
        expires_at=now+timedelta(days=10))
    profile = SourceProfile(id='profile', target='idx', kind='suricata', role='network',
        os_family='unknown', backend='elasticsearch', backend_version='8', captured_at=now,
        field_types={'@timestamp': 'date'}, doc_count=1)
    class Client:
        def __init__(self, _settings):
            pass
        def resolve(self, _pattern):
            return ['idx']
    monkeypatch.setattr(hunt_run, 'ElasticClient', Client)
    monkeypatch.setattr(hunt_run, 'build_profile', lambda *_args, **_kwargs: (profile, None))
    monkeypatch.setattr(hunt_run, 'ai_agent_entry', lambda *_args: {'requested': False})
    hid = hunt_run.create_hunt(settings, now-timedelta(hours=1), now, created_by='analyst', ai_agent=False)
    return repo, lists, meta, hid, now


def test_hunt_creation_pins_lists_and_a_fresh_sweep_replays_the_exact_version(tmp_path, monkeypatch):
    repo, lists, meta, hid, now = create_local_hunt(tmp_path, monkeypatch, [ImportedIndicator('sha256', 'ab'*32)])
    try:
        hunt = repo.get_hunt(hid)
        pin = hunt['manifest']['indicator_lists']
        assert [(row['id'], row['version'], row['digest']) for row in pin['applied']] == [
            (meta['id'], 1, meta['digest'])]
        lists.create_version([ImportedIndicator('sha256', 'cd'*32)], list_id=meta['id'],
            name='Pinned list', source='Partner', author='analyst')
        sweep = Sweep(repo, None, hid, Window(start=now-timedelta(hours=1), end=now),
                      {'idx': None}, stage_dir=tmp_path/'stage')
        try:
            rule = next(row for row in sweep.pack if row.id == 'ioc.indicator_match')
            rule.consume([net_event('file_transfer', file__hash__sha256='ab'*32)])
            matches = list(rule.finalize())
            assert any('version 1' in match.claim and 'ab'*32 in match.claim for match in matches)
            assert not any('cd'*32 in match.claim for match in matches)
            assert meta['digest'] == repo.get_hunt(hid)['manifest']['indicator_lists']['applied'][0]['digest']
        finally:
            sweep.close_stage()
    finally:
        repo.engine.dispose()
