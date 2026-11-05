"""Exact marker capabilities must govern Zeek lookback and coverage claims."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from romulus.config import Settings
from romulus.detect.base import Playbook
from romulus.hunt.sweep import Sweep
from romulus.sources.es import ElasticClient
from romulus.sources.models import Completeness, Window
from romulus.sources.profile import FieldSpec, contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_links import NativePivot
from tests.zeek_source_support import ZeekES

START = datetime(2025, 1, 1, tzinfo=UTC)
WINDOW = Window(start=START, end=START + timedelta(minutes=15))


class HttpProbe(Playbook):
    id = "test.marker_http"
    families = ("http_tx",)

    def match(self, event):
        return []


class FlowProbe(Playbook):
    id = "test.marker_flow"
    families = ("net_flow",)

    def __init__(self):
        super().__init__()
        self.uids = []

    def match(self, event):
        self.uids.append(event.get("zeek.uid"))
        return []


@pytest.mark.parametrize('failure', ['failed','partial','normalization','canonical'])
@pytest.mark.parametrize('layout', ['plain','elastic_ecs'])
def test_incomplete_sweep_inventory_cannot_claim_analyzer_absence(tmp_path, monkeypatch, failure, layout):
    hits = [zf.plain(replace(zf.Conn(),ts=START.timestamp()+10,service='http'), 'conn'),
            zl.plain(replace(zl.CAPTURE_LOSS.with_(percent_lost=0),ts=START.timestamp()+900),'health')]
    shape = 'plain' if layout == 'plain' else 'elastic'
    http = [getattr(zl,shape)(replace(zl.HTTP,ts=START.timestamp()+20),'http')]
    if layout == 'elastic_ecs':
        http[0]['_source'].pop('zeek')
        http[0]['_source']['event']['id'] = 'Chttp'
    contracts = {'network':contract('plain',hits,'network'),'http':contract(shape,http,'http')}
    docs = {'network':hits,'http':http if failure != 'canonical' else []}
    original = Sweep._fetch
    def fetch(self, intent, source):
        outcome = original(self,intent,source)
        if intent.target != 'http':
            return outcome
        if failure in ('failed','partial'):
            return outcome.model_copy(update={'completeness':Completeness(failure),'records':[],
                'returned':0,'reasons':['synthetic analyzer retrieval incomplete'],'error':'synthetic source failure'})
        if failure == 'normalization':
            bad = [{**row,'_source':{**row['_source'],source.time_field:'invalid'}} for row in outcome.records]
            return outcome.model_copy(update={'records':bad})
        return outcome
    monkeypatch.setattr(Sweep,'_fetch',fetch)
    if failure == 'canonical':
        original_canonical = Sweep._canonical_zeek
        def canonical(self, events, raw, reasons):
            selected = original_canonical(self,events,raw,reasons)
            reasons.append(('synthetic cumulative-flow lookup incomplete',frozenset({'net_flow'})))
            return selected
        monkeypatch.setattr(Sweep,'_canonical_zeek',canonical)
    _, detail, rows, _ = run_sweep(tmp_path,docs,contracts,[profile('http',{'zeek.http':1},1)])
    assert detail['unresolved']
    statements = [row['reason'] for row in rows if row.get('connections')]
    assert any('http presence unresolved' in reason for reason in statements)
    assert not any('have no http records' in reason for reason in statements)


def contract(shape, hits, target):
    item = NativePivot(shape, hits).contracts["network"]
    return item.model_copy(update={"target": target, "time_field": "ts" if shape == "plain" else "@timestamp"})


def text_markers(item, keyword):
    fields = dict(item.fields)
    for path in ("_path", "event.dataset", "data_stream.dataset", "event.module", "event.provider", "fileset.name"):
        if path not in fields:
            continue
        fields[path] = fields[path].model_copy(update={
            "type": "text", "ops": ["exists", "missing"], "aggregatable": False,
        })
        if keyword:
            name = path + ".keyword"
            fields[name] = FieldSpec(native=name, natives=(name,), type="keyword",
                                     ops=["eq", "in", "exists", "missing", "contains", "prefix"],
                                     aggregatable=True)
    return item.model_copy(update={"fields": fields})


def profile(target, datasets, count):
    return {"id": "profile-" + target, "kind": "es_index", "target": target,
            "doc_count": count, "datasets": datasets, "notes": []}


def run_sweep(tmp_path, docs, contracts, profiles=()):
    tmp_path.mkdir(parents=True, exist_ok=True)
    backend = ZeekES(docs, {target: contracts[target].time_field for target in docs})
    engine = make_engine(tmp_path / "hunt.db")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h", {"targets": list(docs)}, "digest", "test")
    for item in profiles:
        repo.save_profile("h", item)
    sweep = Sweep(repo, ElasticClient(Settings(home=tmp_path), transport=backend.transport()),
                  "h", WINDOW, contracts, stage_dir=tmp_path / "stage")
    flow = FlowProbe()
    sweep.pack = [HttpProbe(), flow]
    try:
        for target in docs:
            sweep.run_target(target)
        sweep.finalize()
        cells = repo.rule_cells("h")
        audit = repo.latest_audit("h", "hunt.zeek_visibility")
        detail = audit["detail"] if audit else None
        rows = list(repo.zeek_visibility_rows("h", detail["snapshot"]["sha256"])) if detail else []
        return cells, detail, rows, flow.uids
    finally:
        sweep.close_stage()
        engine.dispose()


def refusal_cells(cells, target):
    return [cell for cell in cells if cell["target"] == target and cell["partition"] == "zeek-lookback"]


@pytest.mark.parametrize("shape", ["plain", "elastic"])
@pytest.mark.parametrize("keyword", [False, True])
def test_text_markers_use_reported_keyword_or_name_unresolved_coverage(tmp_path, shape, keyword):
    writer = getattr(zf, shape)
    conn = writer(replace(zf.Conn(), uid=zl.UID_HTTP, ts=START.timestamp() + 60,
                          duration=30, service="http"), "conn")
    http = getattr(zl, shape)(replace(zl.HTTP, ts=START.timestamp() + 60), "http")
    pre = writer(replace(zf.Conn(), uid="Cpre", ts=START.timestamp() - 3600,
                         duration=7200, service="http"), "pre")
    hits = [conn, http, pre]
    item = text_markers(contract(shape, hits, "network"), keyword)
    cells, detail, rows, uids = run_sweep(tmp_path, {"network": hits}, {"network": item})
    assert detail is not None
    assert any(cell["rule_id"] == HttpProbe.id and cell["evaluated"] == 1 for cell in cells)
    assert rows
    if keyword:
        assert "Cpre" in uids
        assert not refusal_cells(cells, "network")
        assert detail["unresolved"] == []
        assert any("no health record" in row["reason"] and row["partial"] for row in rows)
    else:
        assert "Cpre" not in uids
        refused = refusal_cells(cells, "network")
        assert {cell["rule_id"] for cell in refused} == {HttpProbe.id, FlowProbe.id}
        assert all(cell["state"] == "evaluated_partial" for cell in refused)
        assert any("network" in reason and "markers" in reason and "unresolved" in reason
                   for reason in detail["unresolved"])
    assert not any("have no http records" in row["reason"] for row in rows)


@pytest.mark.parametrize("http_present", [False, True])
def test_mixed_targets_never_claim_http_absent_when_marker_search_was_refused(tmp_path, http_present):
    conn = zf.elastic(replace(zf.Conn(), uid=zl.UID_HTTP, ts=START.timestamp() + 60,
                              duration=30, service="http"), "conn")
    health = zl.elastic(replace(zl.CAPTURE_LOSS.with_(percent_lost=0.0),
                                ts=START.timestamp() + 900), "health")
    http = zl.elastic(replace(zl.HTTP, ts=START.timestamp() + 60), "http")
    good = contract("elastic", [conn, health], "network")
    bad = text_markers(contract("elastic", [http], "omitted-http"), False)
    docs = {"network": [conn, health], "omitted-http": [http] if http_present else []}
    profiles = [] if http_present else [profile("omitted-http", {"zeek.http": 1}, 1)]
    cells, detail, rows, _uids = run_sweep(tmp_path, docs, {"network": good, "omitted-http": bad}, profiles)
    assert detail is not None
    assert any("omitted-http" in reason and "markers" in reason for reason in detail["unresolved"])
    assert {cell["rule_id"] for cell in refusal_cells(cells, "omitted-http")} == {
        HttpProbe.id, FlowProbe.id,
    }
    assert not any("have no http records" in row["reason"] for row in rows)
    if not http_present:
        assert any("http presence unresolved" in row["reason"] for row in rows)


def test_unpopulated_zeek_fields_in_shared_template_do_not_create_false_partiality(tmp_path):
    conn = zf.elastic(replace(zf.Conn(), ts=START.timestamp() + 60, duration=30, service="http"), "conn")
    health = zl.elastic(replace(zl.CAPTURE_LOSS.with_(percent_lost=0.0),
                                ts=START.timestamp() + 900), "health")
    template = zl.elastic(replace(zl.HTTP, ts=START.timestamp() + 60), "template")
    good_http = zl.elastic(replace(zl.HTTP, ts=START.timestamp() + 60), "http")
    bad = text_markers(contract("elastic", [template], "unrelated"), False)
    host_fields = contract_from_types("unrelated", {
        "@timestamp": "date", "host.name": "keyword", "event.dataset": "text",
    }, role="host", os_family="linux")
    bad = bad.model_copy(update={"fields": {**bad.fields, **host_fields.fields}, "role": "host"})
    stamp = START.timestamp() + 60
    host = {"_index": "unrelated", "_id": "auth", "_source": {
        "@timestamp": datetime.fromtimestamp(stamp, UTC).isoformat(), "host": {"name": "first"},
        "event": {"dataset": "linux.audit", "original":
                  f'type=USER_LOGIN msg=audit({stamp}:1): pid=900 uid=0 auid=1001 '
                  'ses=42 acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.8 res=success'},
    }}
    cells, detail, _rows, _uids = run_sweep(
        tmp_path, {"network": [conn, health, good_http], "unrelated": [host]},
        {"network": contract("elastic", [conn, health, good_http], "network"), "unrelated": bad},
        [profile("unrelated", {"linux.audit": 1}, 1)],
    )
    assert detail is not None
    assert detail["unresolved"] == []
    assert not refusal_cells(cells, "unrelated")
    assert not any(cell["target"].startswith("zeek:") and cell["state"] == "evaluated_partial" for cell in cells)


def test_profile_verified_zeek_target_without_window_events_still_names_marker_refusal(tmp_path):
    http = zl.elastic(replace(zl.HTTP, ts=START.timestamp() - 86400), "outside")
    bad = text_markers(contract("elastic", [http], "profile-only"), False)
    cells, detail, _rows, _uids = run_sweep(
        tmp_path, {"profile-only": []}, {"profile-only": bad},
        [profile("profile-only", {"zeek.http": 1}, 1)],
    )
    assert detail is not None
    assert any("profile-only" in reason and "markers" in reason for reason in detail["unresolved"])
    refused = refusal_cells(cells, "profile-only")
    assert {cell["rule_id"] for cell in refused} == {HttpProbe.id, FlowProbe.id}
    assert all(cell["state"] == "evaluated_partial" for cell in refused)
