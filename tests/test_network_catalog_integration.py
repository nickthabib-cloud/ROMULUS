"""Raw protocol evidence reaches the registered rules and retains its supported lane."""
import json

import pytest

from romulus.decide.policy import decide
from romulus.detect.bounded import StateBudget
from romulus.detect.netdef import SiteNetworks, current, install
from romulus.detect.registry import ALL_PLAYBOOKS, bind_windows_site, pack_manifest
from romulus.evidence.normalize import normalize_hits
from romulus.site import COLLECTION_SCHEMA, validate_site_content
from tests.test_arkime_sessions import session
from tests.test_suricata_protocols import BASE, hit


@pytest.fixture
def registered(tmp_path):
    previous = current()
    install(SiteNetworks.from_lists(["10.0.0.0/8"]))
    rules = {cls.id: cls() for cls in ALL_PLAYBOOKS if cls.id in {"network.smb_impact", "network.service_catalog"}}
    for rule in rules.values():
        rule.budget = StateBudget(tmp_path / rule.id, disk_total=128 * 2**20, reserve=0, memory_total=2**20)
    yield rules
    for rule in rules.values():
        rule.release_state()
        rule.close_spill()
    install(previous)


def test_rules_registered_as_network_observations(registered):
    assert set(registered) == {"network.smb_impact", "network.service_catalog"}
    assert all(rule.anchor_class == "network_observation" for rule in registered.values())
    assert all(not rule.assures_negative for rule in registered.values())
    manifests = {row["id"]: row for row in pack_manifest()}
    assert manifests["network.smb_impact"]["families"] == ["smb_tx"]
    assert "net_session" in manifests["network.service_catalog"]["families"]


def test_enriched_suricata_rename_records_reach_high_critical(registered):
    # Native Suricata rename records need externally supplied share context for this rule.
    docs = [hit("smb", {"command": "SMB2_COMMAND_SET_INFO", "share": r"\\server\docs",
                       "rename": {"from": f"dir/file-{i}.txt", "to": f"dir/file-{i}.locked"}}, nid=f"smb-{i}")
            for i in range(100)]
    events, skips, errors = normalize_hits(docs)
    assert len(events) == 100 and not skips and not errors
    rule = registered["network.smb_impact"]
    matches = [*rule.consume(events), *rule.finalize()]
    assert len(matches) == 1
    decision = decide(matches[0], "synthetic-hunt")
    assert decision.admitted and decision.lane == "high" and decision.severity == "critical"


def test_suricata_dns_and_arkime_sni_reach_approved_leads(registered):
    eve = {**BASE, "event_type": "dns", "dns": {"type": "query", "rrname": "abc.ngrok-free.app", "rrtype": "A"}}
    dns = {"_index": "synthetic", "_id": "dns", "_source": {
        "@timestamp": BASE["timestamp"], "event": {"dataset": "suricata.eve", "original": json.dumps(eve)}}}
    arkime = session("sni", src="10.0.0.5")
    arkime["_source"].update(protocol=["tcp", "tls"], http={"host": ["relay.net.anydesk.com"]})
    events, skips, errors = normalize_hits([dns, arkime])
    assert len(events) == 2 and not skips and not errors
    rule = registered["network.service_catalog"]
    site = validate_site_content({"schema": COLLECTION_SCHEMA, "approved_remote_access": ["anydesk", "ngrok"]})
    bind_windows_site([rule], site)
    found = {match.group_key: match for match in rule.consume(events)}
    for match in rule.finalize():
        match.fleet_hosts = tuple(match.fleet_hosts)
        found[match.group_key] = match
    assert found
    for match in found.values():
        decision = decide(match, "synthetic-hunt")
        assert decision.admitted and decision.lane == "lead"
        assert any("approved" in note.casefold() for note in match.notes)
    assert any("anydesk" in match.claim.casefold() for match in found.values())
    assert any("ngrok" in match.claim.casefold() for match in found.values())


def test_native_suricata_rename_without_share_remains_unresolved(registered):
    docs = [hit("smb", {"command": "SMB2_COMMAND_SET_INFO", "tree_id": 1, "session_id": 2,
                       "rename": {"from": f"dir/file-{i}.txt", "to": f"dir/file-{i}.locked"}}, nid=f"native-{i}")
            for i in range(100)]
    events, skips, errors = normalize_hits(docs)
    assert len(events) == 100 and not skips and not errors
    rule = registered["network.smb_impact"]
    assert not [*rule.consume(events), *rule.finalize()]
    assert rule.missing_required == 100
