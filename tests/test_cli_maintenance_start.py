"""CLI creation and claim are fenced together before maintenance can intervene."""
from threading import Event, Thread
from types import SimpleNamespace

from romulus import cli
from romulus.config import Settings
from romulus.hunt import run as hunt_run
from romulus.store import db
from romulus.store.repo import Repo


def setup(monkeypatch, tmp_path):
    engine = db.make_engine(tmp_path / 'romulus.db')
    db.migrate(engine)
    repo = Repo(engine)
    settings = Settings(home=tmp_path)
    monkeypatch.setattr(cli, 'load_settings', lambda _: settings)
    monkeypatch.setattr(hunt_run, 'open_repo', lambda _: repo)
    monkeypatch.setattr(hunt_run, 'ai_agent_entry', lambda *_: {})
    created, ran = [], []

    def create(*args, **kwargs):
        created.append(True)
        repo.create_hunt('h2', {}, 'digest', 'cli:test')
        return 'h2'

    def run(_settings, hid, **kwargs):
        current = repo.get_hunt(hid)
        assert current['execution_state'] == 'running'
        assert current['lease_owner'] == kwargs['claimed_owner']
        ran.append(True)
        return {'execution_state': 'completed', 'detection_result': 'findings', 'lanes': {}, 'stats': {}}

    monkeypatch.setattr(hunt_run, 'create_hunt', create)
    monkeypatch.setattr(hunt_run, 'run_hunt', run)
    args = SimpleNamespace(action='start', no_agent=True, agent_mode=None, start='2026-01-01T00:00:00Z',
                           end='2026-01-02T00:00:00Z', style='broad', hypothesis=None, no_expand=True,
                           env_file=str(tmp_path / '.env'), json=False)
    return repo, args, created, ran


def test_cli_waits_before_creation_and_claims_under_the_same_lease(monkeypatch, tmp_path, capsys):
    repo, args, created, ran = setup(monkeypatch, tmp_path)
    waiting = Event()
    original = db.maintenance_lease

    def lease(engine, **kwargs):
        if kwargs.get('on_wait'):
            callback = kwargs['on_wait']
            def notify():
                waiting.set()
                callback()
            kwargs['on_wait'] = notify
        return original(engine, **kwargs)

    monkeypatch.setattr(db, 'maintenance_lease', lease)
    result = []
    with original(repo.engine):
        thread = Thread(target=lambda: result.append(cli.cmd_hunt(args)))
        thread.start()
        assert waiting.wait(3)
        assert created == [] and repo.get_hunt('h2') is None
    thread.join(5)
    assert not thread.is_alive()
    assert result == [0] and created == [True] and ran == [True]
    assert 'Waiting up to 30 seconds' in capsys.readouterr().err


def test_cli_bounded_maintenance_timeout_creates_no_planned_hunt(monkeypatch, tmp_path, capsys):
    repo, args, created, ran = setup(monkeypatch, tmp_path)
    original = db.maintenance_lease
    monkeypatch.setattr(db, 'maintenance_lease', lambda engine, **kwargs: original(
        engine, **{**kwargs, 'wait_seconds': 0.02}))
    result = []
    with original(repo.engine):
        thread = Thread(target=lambda: result.append(cli.cmd_hunt(args)))
        thread.start()
        thread.join(3)
        assert not thread.is_alive()
    assert result == [cli.EXIT_FAIL] and created == [] and ran == []
    assert repo.get_hunt('h2') is None
    assert 'hunt not created: Database maintenance is active' in capsys.readouterr().err
