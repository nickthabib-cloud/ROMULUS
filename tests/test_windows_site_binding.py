"""Frozen site facts reach new directory rules at sweep and expansion construction boundaries."""
from datetime import timedelta
from types import SimpleNamespace

from romulus.detect import registry
from romulus.detect.windows_directory_events import DirectoryReplicationAccess
from romulus.hunt import expansion as expansion_module
from romulus.hunt import sweep as sweep_module
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.sweep import Sweep
from romulus.site import SiteFacts
from romulus.sources.models import Window
from tests.test_context_catalog import _repo, _seed_anchor, _seed_link
from tests.windows_event_support import START, event

FACTS = SiteFacts(True, "frozen-test", {}, (), ("dc01.example.test",), ("name:example\\sync",))


def replication():
    return event("directory_access", 4662, **{
        "directory.rights.guids": ["1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"],
        "directory.access.access_mask": 0x100, "directory.object.server": "DS",
        "user.entity_id": "sid:s-1-5-21-1-2-3-1100", "user.name": "alice", "user.domain": "example"})


def test_pack_binding_uses_the_supplied_snapshot_without_reloading_configuration():
    rule = DirectoryReplicationAccess()
    bind = getattr(registry, "bind_windows_site", lambda pack, facts: pack)
    bind([rule], FACTS)
    assert rule.site_facts is FACTS and rule.judge(replication())[0].lane == "high"


def test_sweep_passes_its_frozen_site_facts_into_the_new_rule(tmp_path, monkeypatch):
    rule = DirectoryReplicationAccess()
    monkeypatch.setattr(sweep_module, "fresh_pack", lambda: [rule])
    sweep = Sweep(_repo(), None, "h1", Window(start=START, end=START+timedelta(minutes=1)), {},
                  stage_dir=tmp_path, site_facts=FACTS)
    assert sweep.pack[0].site_facts is FACTS
    assert sweep.pack[0].judge(replication())[0].lane == "high"
    sweep.close_stage()


def test_expansion_binds_the_existing_executor_facts_before_direct_detection(monkeypatch):
    repo = _repo()
    process = event("process_exec", 4688)
    evidence = replication()
    _seed_anchor(repo, "h1", "F-A", "win.source", [process], host=process.host)
    repo.save_evidence("h1", [evidence], {evidence.raw[0].key: {"marker": "replication"}}, None)
    _seed_link(repo, "h1", "L-facts", "F-A", [evidence], link_type="source_ip")
    rule = DirectoryReplicationAccess()
    rule.one_shot = True
    monkeypatch.setattr(expansion_module, "fresh_direct_pack", lambda: [rule])
    fetcher = SimpleNamespace(executor=SimpleNamespace(site_facts=FACTS))
    engine = ExpansionEngine(repo, "h1", Window(start=START, end=START+timedelta(minutes=1)), fetcher)
    result = SimpleNamespace(id="L-facts", link_type="source_ip", strength="observed", event_ids=[evidence.id], task_ids=[])
    rows = engine._evaluate(repo.candidate("F-A"), result)
    assert rule.site_facts is FACTS
    assert len(rows) == 1 and rows[0]["lane"] == "high"
