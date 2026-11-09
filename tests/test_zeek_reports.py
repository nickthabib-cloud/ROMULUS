"""Immutable visibility references survive JSON roundtrip and all report renderers."""
import hashlib
import json
from xml.etree import ElementTree
from zipfile import ZipFile

from romulus.report.bundle import write_reports
from romulus.report.manifest import publish_revision
from tests.test_report import _repo_with_finding


def test_visibility_report_roundtrip_exports_complete_snapshot_and_docx_statements(tmp_path):
    repo, _ = _repo_with_finding()
    ref=repo.save_zeek_visibility('h1', ({'sensor':'sensor-a','family':'http_tx','partial':True,
        'reason':f'sensor-a interval {i}: estimated 2.3 % capture loss; SMB analyzer records missing'} for i in range(10001)))
    repo.audit('system','hunt.zeek_visibility','h1',{'snapshot':ref,'notes':['connections lookback 24 hours'],'unresolved':[]})
    manifest=json.loads(json.dumps(publish_revision(repo,'h1','test')))
    assert manifest['coverage']['zeek_visibility']['snapshot']==ref
    paths=write_reports(repo,manifest,tmp_path)
    blob=(tmp_path/ref['filename']).read_bytes()
    assert hashlib.sha256(blob).hexdigest()==ref['sha256']
    assert len(blob.splitlines())==10001
    assert 'interval 10000:' in paths['md'].read_text(encoding='utf-8')
    with ZipFile(paths['docx']) as archive:
        doc=ElementTree.fromstring(archive.read('word/document.xml'))
    text=' '.join(doc.itertext())
    assert 'estimated 2.3 % capture loss' in text
    assert ref['filename'] in text
    assert '9951 omitted from this preview' in text
    # Copy just the shareable bundle: the relative DOCX and Markdown links still resolve.
    import shutil
    copied=tmp_path/'copied';copied.mkdir()
    for source in [*paths.values(),tmp_path/ref['filename']]:
        shutil.copy2(source,copied/source.name)
    with ZipFile(copied/paths['docx'].name) as archive:
        rels=ElementTree.fromstring(archive.read('word/_rels/document.xml.rels'))
    targets=[rel.attrib['Target'] for rel in rels if rel.attrib.get('TargetMode')=='External']
    assert targets==[ref['filename']]
    assert hashlib.sha256((copied/targets[0]).read_bytes()).hexdigest()==ref['sha256']
    assert f"]({ref['filename']})" in (copied/paths['md'].name).read_text(encoding='utf-8')

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest


@pytest.mark.parametrize('shape',['malcolm','elastic','security_onion','plain'])
def test_one_native_hunt_visibility_certificate_and_all_renderers_after_reopen(tmp_path,shape):
    import secrets

    from fastapi.testclient import TestClient

    from romulus.config import Settings
    from romulus.hunt.expansion import ExpansionEngine
    from romulus.hunt.links import LinkFetcher
    from romulus.hunt.pivot import PivotExecutor
    from romulus.hunt.run import open_repo
    from romulus.hunt.sweep import Sweep
    from romulus.sources.es import ElasticClient
    from romulus.sources.models import Window
    from romulus.web.app import create_app
    from romulus.web.auth import create_user
    from tests.fixtures import zeek_factory as zf
    from tests.fixtures import zeek_logs as zl
    from tests.test_zeek_links import NativePivot
    from tests.test_zeek_twins import tls_session
    from tests.zeek_source_support import ZeekES
    settings=Settings(home=tmp_path,secret_key=secrets.token_urlsafe(32))
    repo=open_repo(settings)
    now=datetime.fromtimestamp(zl.T0,UTC)
    window=Window(start=now-timedelta(seconds=1),end=now+timedelta(minutes=15))
    writer=getattr(zl,shape)
    tls=[tls_session(i)[0] for i in range(3)]
    hits=[writer(row,str(i)) for i,row in enumerate(tls)]
    hits += [writer(replace(zl.X509.with_(fingerprint='3c'*32),ts=zl.T0-86400),'cert'),
             getattr(zf,shape)(replace(zf.Conn(),ts=zl.T0,duration=60,service='smb',uid=tls[0].zeek['uid'],missed_bytes=10),'conn')]
    health={'peer':'worker','ts_delta':1800,'gaps':23,'acks':1000,'percent_lost':2.3}
    end=(now+timedelta(minutes=16)).isoformat()
    if shape=='malcolm':
        source={'@timestamp':end,'node':zl.SENSOR,'event':{'provider':'zeek','dataset':'capture_loss'},'zeek':{'capture_loss':health}}
    elif shape=='elastic':
        source={'@timestamp':end,'agent':{'name':zl.SENSOR},'data_stream':{'dataset':'zeek.capture_loss'},
                'event':{'dataset':'zeek.capture_loss'},'zeek':{'capture_loss':health}}
    elif shape=='plain':
        source={'_path':'capture_loss','ts':now.timestamp()+960,**health}
    else:
        source=None
    if source:
        hits.append({'_index':'network','_id':'health','_source':source})
    native=NativePivot(shape,hits)
    contract=native.contracts['network'].model_copy(update={'time_field':'ts' if shape=='plain' else '@timestamp'})
    backend=ZeekES({'network':hits},{'network':contract.time_field})
    client=ElasticClient(settings,transport=backend.transport())
    base={'targets':['network'],'style':'broad','original_input':{},'window':window.model_dump(mode='json'),
          'source_profiles':{},'ai_agent':{'requested':False},'expansion':{'enabled':True},'pack':{'version':'test'},
          'normalizer':'test','policy':'test','model':{},'romulus_version':'test'}
    repo.create_hunt('zeek',base,'digest','test')
    sweep=Sweep(repo,client,'zeek',window,{'network':contract},stage_dir=tmp_path/'stage')
    from romulus.detect.indicators import IndicatorMatch, load_indicators
    indicator_dir=tmp_path/'indicators';indicator_dir.mkdir()
    (indicator_dir/'list.yaml').write_text("schema_version: 1\nindicators:\n  - {id: test.c2, kind: domain, "
        "values: [c2.example.net], label: synthetic C2, severity: high, lane: high}\n",encoding='utf-8')
    rule=IndicatorMatch(load_indicators(indicator_dir))
    rule.spill_dir=tmp_path/'stage';rule.budget=sweep.budget;rule.window_start=window.start
    sweep.pack=[rule if pb.id==rule.id else pb for pb in sweep.pack]
    try:
        sweep.run_target('network');sweep.finalize()
    finally:
        sweep.close_stage()
    assert any(row['rule_id']=='net.tls_self_signed_certificate_outbound' for row in repo.candidates('zeek'))
    assert any('missed_bytes' in note for candidate in repo.candidates('zeek')
               for note in candidate['gate_results'].get('_notes',[]))
    pivot=PivotExecutor(repo,client,'zeek',{'network':contract},stage_dir=tmp_path/'pivot')
    engine=ExpansionEngine(repo,'zeek',window,LinkFetcher(pivot,window.start,window.end),max_depth=1,max_source_queries=400)
    result=engine.run()
    assert any(row['link_type']=='certificate' and row['status']=='complete' for row in repo.expansion_links('zeek')), (result,repo.candidates('zeek'),repo.expansion_links('zeek'))
    manifest=json.loads(json.dumps(publish_revision(repo,'zeek','test')))
    fresh=open_repo(settings)
    paths=write_reports(fresh,manifest,settings.reports_dir/'zeek')
    with ZipFile(paths['docx']) as archive:
        text=' '.join(ElementTree.fromstring(archive.read('word/document.xml')).itertext())
    md=paths['md'].read_text(encoding='utf-8')
    expected='no health record' if shape=='security_onion' else '2.3 % capture loss'
    for rendered in (json.dumps(manifest),md,text):
        assert expected in rendered
        assert 'have no smb_* records in scope' in rendered.replace(chr(92),''), manifest['coverage']['zeek_visibility']
        assert '30 day certificate lookback' in rendered
    password=secrets.token_urlsafe(20);create_user(fresh.engine,'reader',password,'analyst')
    web=TestClient(create_app(settings));web.post('/login',data={'username':'reader','password':password})
    page=web.get('/hunts/zeek')
    assert page.status_code==200
    assert expected in page.text and 'have no smb_* records in scope' in page.text and 'certificate' in page.text
    ref=manifest['coverage']['zeek_visibility']['snapshot']
    response=web.get('/reports/zeek/'+ref['filename'])
    assert response.status_code==200
    assert hashlib.sha256(response.content).hexdigest()==ref['sha256']
