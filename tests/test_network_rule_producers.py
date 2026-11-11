"""Network lateral and rate rules judge Suricata protocol records with the facts Zeek and Suricata type alike."""
import importlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from romulus.evidence.normalize import normalize_hits
from tests.fixtures import zeek_logs as zl
from tests.test_malcolm_suricata import filebeat_hit
from tests.test_zeek_lateral_rules import facts
from tests.test_zeek_windows_protocols import normalize
from tests.windows_process_support import run

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
EFSRPC = "c681d488-d850-11d0-8c52-00c04fd90f7e"
NETLOGON = "12345678-1234-abcd-ef00-01234567cffb"
SRVSVC = "4b324fc8-1670-01d3-1278-5a47bf6ee188"
SVCCTL = "367abb81-9844-35f1-ad32-98f038001003"
INTERNAL = facts(internal_networks=("10.0.0.0/8",))


def suricata(et, block, n=0, *, source="10.0.0.5", destination="10.0.0.10", port=445, seconds=1, family=None):
    stamp = (T0 + timedelta(seconds=n * seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    eve = {"timestamp": stamp, "src_ip": source, "src_port": 51000 + n % 10000, "dest_ip": destination,
           "dest_port": port, "proto": "TCP", "flow_id": 1000 + n, "event_type": et, et: block}
    events, skips, errors = normalize_hits([filebeat_hit(eve, f"eve-{et}-{n}")])
    assert not skips and not errors
    [event] = [event for event in events if family is None or event.family == family]
    assert event.normalizer.startswith("suricata-eve@")
    return event


def rpc(uuid, opnum, n=0, **where):
    # A call carried over an SMB named pipe: Suricata's SMB logger writes the bound interface beside the opnum
    # (rust/src/smb/log.rs). A standalone DCERPC request record carries only the opnum and is not classified.
    block = {"command": "SMB2_COMMAND_IOCTL", "dcerpc": {"request": "REQUEST", "opnum": opnum,
             "req": {"frag_cnt": 1, "stub_data_size": 80}, "interfaces": [{"uuid": uuid}]}}
    return suricata("smb", block, n, family="rpc_tx", **where)


def lateral(name, events, site=INTERNAL):
    owner = getattr(importlib.import_module("romulus.detect.zeek_lateral"), name)()
    owner.site_facts = site
    try:
        return run(owner, [[event] for event in events])
    finally:
        owner.release_state()


def rate(name, events):
    owner = getattr(importlib.import_module("romulus.detect.zeek_rates"), name)()
    try:
        return run(owner, [[event] for event in events])
    finally:
        owner.release_state()


def test_a_suricata_coercion_call_is_high():
    [match] = lateral("WireCoercionCall", [rpc(EFSRPC, 0)])
    assert match.proposed_lane == "high" and "coercion" in match.claim


def test_a_suricata_service_creation_call_is_a_remote_administration_finding():
    [match] = lateral("RpcRemoteAdminCall", [rpc(SVCCTL, 12)])
    assert "service_create" in match.claim


@pytest.mark.parametrize("source,name,lane", [("10.0.0.5", "InternalRdpSession", "lead"),
                                              ("203.0.113.9", "RdpRemoteSession", "high")])
def test_suricata_rdp_sessions_are_judged_by_direction(source, name, lane):
    session = suricata("rdp", {"event_type": "initial_request", "cookie": "admin"}, source=source, port=3389)
    [match] = lateral(name, [session])
    assert match.proposed_lane == lane


def test_a_standalone_suricata_request_without_its_interface_is_not_classified():
    request = suricata("dcerpc", {"request": "REQUEST", "req": {"opnum": 0}})
    assert request.get("rpc.op_class") is None
    assert lateral("WireCoercionCall", [request]) == []


def test_rules_that_need_facts_suricata_does_not_record_stay_zeek_only():
    lateral_rules = importlib.import_module("romulus.detect.zeek_lateral")
    assert lateral_rules.TgsLongLifetime.producers == ("zeek-ecs",)      # Suricata does not type the requested till
    assert lateral_rules.VncRemoteSession.producers == ("zeek-ecs",)     # Suricata RFB records are not normalized
    smb = importlib.import_module("romulus.detect.zeek_smb")
    assert not hasattr(smb.AdminSharePeWrite, "producers") or smb.AdminSharePeWrite.producers == ("zeek-ecs",)


def test_a_record_another_producer_wrote_is_not_read():
    event = rpc(EFSRPC, 0)
    assert lateral("WireCoercionCall", [event.model_copy(update={"normalizer": "arkime@1"})]) == []
    assert lateral("WireCoercionCall", [event.model_copy(update={"normalizer": "lab-ecs@18"})]) == []


def test_a_raw_reference_count_is_kept_per_sensor_so_two_sensors_do_not_double_it():
    zeek = [normalize(zl.WRITERS["plain"](replace(zl.DCE_RPC.with_(endpoint="netlogon",
            operation="NetrServerAuthenticate3", uid=f"Czero{n:010d}"), ts=zl.T0 + n), f"z{n}")) for n in range(30)]
    eve = [rpc(NETLOGON, 26, n, source=zl.CLIENT, destination=zl.DC) for n in range(30)]
    assert {event.get("source.ip") for event in zeek} == {zl.CLIENT}
    assert rate("ZerologonRate", zeek + eve) == []
    [match] = rate("ZerologonRate", [rpc(NETLOGON, 26, n, source=zl.CLIENT, destination=zl.DC) for n in range(50)])
    assert match.proposed_lane == "high"


def test_a_distinct_host_count_is_shared_across_sensors():
    zeek = [normalize(zl.WRITERS["plain"](replace(zl.DCE_RPC.with_(endpoint="srvsvc", operation="NetrSessionEnum",
            uid=f"Cenum{n:010d}", **{"id.resp_h": f"10.0.4.{n}"}), ts=zl.T0 + n), f"z{n}")) for n in range(5)]
    eve = [rpc(SRVSVC, 12, n, source=zl.CLIENT, destination=f"10.0.4.{n}") for n in range(5, 10)]
    hosts = zeek + eve
    [match] = rate("RpcHostEnumerationFanout", hosts)
    assert match.proposed_lane == "lead" and "at least 10 distinct hosts" in match.claim
    assert rate("RpcHostEnumerationFanout", hosts[:9]) == []
