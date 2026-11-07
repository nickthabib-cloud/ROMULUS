"""The Sigma CLI checks a live lead account for activation and retirement."""
import json
import secrets

import pytest
from sqlalchemy import select

from romulus import cli
from romulus.config import Settings
from romulus.hunt.run import open_repo
from romulus.store import schema as t
from romulus.web.auth import create_user
from tests.test_sigma_store import document, fixture


@pytest.fixture
def local_cli(tmp_path, monkeypatch):
    import yaml
    settings = Settings(home=tmp_path/'home', secret_key=secrets.token_urlsafe(32))
    monkeypatch.setattr(cli, 'load_settings', lambda _: settings)
    monkeypatch.setenv('USER', 'offline-user')
    repo = open_repo(settings)
    create_user(repo.engine, 'lead', 'long-test-password', 'lead')
    create_user(repo.engine, 'analyst', 'long-test-password', 'analyst')
    root = tmp_path/'rules'
    root.mkdir()
    (root/'synthetic.yml').write_text(yaml.safe_dump(document()), encoding='utf-8')
    yield repo, root
    repo.engine.dispose()


def test_cli_import_list_show_and_lead_activation(local_cli, tmp_path, monkeypatch, capsys):
    import getpass
    repo, root = local_cli
    assert cli.main(['sigma','import',str(root),'--upstream','Local','--commit','a'*40]) == 0
    rid = json.loads(capsys.readouterr().out)['rules'][0]['id']
    assert cli.main(['sigma','list']) == 0
    assert json.loads(capsys.readouterr().out)[0]['status'] == 'draft'
    assert cli.main(['sigma','show',rid]) == 0
    assert json.loads(capsys.readouterr().out)['upstream_path'] == 'synthetic.yml'
    positive = fixture(tmp_path,'positive.json')
    benign = fixture(tmp_path,'benign.json',r'C:\Tools\benign.exe')
    monkeypatch.setattr(getpass,'getpass',lambda _prompt:'long-test-password')
    args = ['sigma','activate',rid,'--positive',str(positive),'--benign',str(benign),'--user','lead']
    assert cli.main(args+['--lane','high','--reason','Reviewed mission predicate']) == 0
    assert json.loads(capsys.readouterr().out)['lane'] == 'high'
    assert cli.main(['sigma','retire',rid,'--user','lead']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'retired'
    with repo.engine.connect() as c:
        assert c.execute(select(t.audit_event.c.actor).where(t.audit_event.c.action=='sigma.activate')).scalar_one() == 'lead'


@pytest.mark.parametrize('account,password,disabled', [('analyst','long-test-password',False),
    ('lead','wrong-password',False),('lead','long-test-password',True)])
def test_cli_refuses_nonlead_bad_password_and_disabled_account(local_cli,tmp_path,monkeypatch,capsys,
    account,password,disabled):
    import getpass
    repo,root=local_cli
    assert cli.main(['sigma','import',str(root),'--upstream','Local','--commit','a'*40]) == 0
    rid=json.loads(capsys.readouterr().out)['rules'][0]['id']
    if disabled:
        with repo.engine.begin() as c:
            c.execute(t.user.update().where(t.user.c.username==account).values(disabled=1))
    monkeypatch.setattr(getpass,'getpass',lambda _prompt:password)
    positive=fixture(tmp_path,'positive.json')
    benign=fixture(tmp_path,'benign.json',r'C:\Tools\benign.exe')
    assert cli.main(['sigma','activate',rid,'--positive',str(positive),'--benign',str(benign),'--user',account]) == 1
    assert 'lead' in capsys.readouterr().err.lower()
    assert cli.main(['sigma','retire',rid,'--user',account]) == 1
    assert password not in capsys.readouterr().err
    with repo.engine.connect() as c:
        assert c.execute(select(t.sigma_rule.c.status)).scalar_one() == 'draft'


def test_cli_unknown_id_and_local_input_rejections_are_safe(local_cli,capsys):
    assert local_cli
    assert cli.main(['sigma','show','unknown']) == 1
    assert 'unknown' not in capsys.readouterr().err.lower()
    assert cli.main(['sigma','import','//remote/share','--upstream','Local','--commit','a'*40]) == 1
    assert '//remote/share' not in capsys.readouterr().err
