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
def test_the_client_initial_rdp_request_is_judged_by_its_direction(source, name, lane):
    request = suricata("rdp", {"event_type": "initial_request", "cookie": "admin"}, source=source, port=3389)
    [match] = lateral(name, [request])
    assert match.proposed_lane == lane


@pytest.mark.parametrize("subtype", ["initial_response", "connect_response", "tls_handshake"])
@pytest.mark.parametrize("name", ["InternalRdpSession", "RdpRemoteSession"])
def test_suricata_rdp_server_records_are_not_judged(name, subtype):
    # written in the packet's direction: the server is their source
    response = suricata("rdp", {"event_type": subtype}, source="203.0.113.9", destination="10.0.0.5", port=51000)
    assert lateral(name, [response]) == []


def _setup(n, user, status, *, source=zl.CLIENT):
    block = {"command": "SMB2_COMMAND_SESSION_SETUP", "ntlmssp": {"user": user, "domain": "EXAMPLE", "host": "WS01"}}
    if status is not None:
        block["status"] = status
    return suricata("smb", block, n, source=source, family="ntlm_tx")


def test_logons_both_sensors_record_never_read_as_a_spray_followed_by_a_success():
    zeek = [normalize(zl.WRITERS["plain"](replace(zl.NTLM.with_(uid=f"Cntlm{n:010d}", username=f"user{n}",
            success=True), ts=zl.T0 + n), f"z{n}")) for n in range(12)]
    eve = [_setup(n, f"user{n}", "STATUS_SUCCESS") for n in range(12)]
    assert eve[0].get("ntlm.success") is True
    assert rate("NtlmPasswordSpray", zeek + eve) == []
    assert rate("NtlmPasswordGuessing", [_setup(n, "svc", "STATUS_SUCCESS") for n in range(25)]) == []


def test_suricata_logon_failures_for_many_users_are_a_spray_and_a_later_success_raises_it():
    failures = [_setup(n, f"user{n}", "STATUS_LOGON_FAILURE") for n in range(12)]
    [lead] = rate("NtlmPasswordSpray", failures)
    assert lead.proposed_lane == "lead"
    [high] = rate("NtlmPasswordSpray", failures + [_setup(13, "user3", "STATUS_SUCCESS")])
    assert high.proposed_lane == "high"


def test_an_unrecorded_suricata_outcome_counts_as_an_attempt_never_a_failure_or_success():
    unknown = [_setup(n, f"user{n}", None) for n in range(12)]
    assert all(event.get("ntlm.success") is None for event in unknown)
    [match] = rate("NtlmPasswordSpray", unknown)
    assert match.proposed_lane == "lead"


def test_a_standalone_suricata_request_without_its_interface_is_not_classified():
    request = suricata("dcerpc", {"request": "REQUEST", "req": {"opnum": 0}})
    assert request.get("rpc.op_class") is None
    assert lateral("WireCoercionCall", [request]) == []


def test_rules_that_need_facts_suricata_does_not_record_stay_zeek_only():
    lateral_rules = importlib.import_module("romulus.detect.zeek_lateral")
    assert lateral_rules.TgsLongLifetime.producers == ("zeek-ecs",)      # Suricata does not type the requested till
    assert lateral_rules.VncRemoteSession.producers == ("zeek-ecs",)     # Suricata RFB records are not normalized
    # Kerberos record kinds (request, reply, error) are not typed, so a rate would count one exchange more than once
    rates = importlib.import_module("romulus.detect.zeek_rates")
    for name in ("Rc4TgsFanout", "KerberosPrincipalEnumeration"):
        assert getattr(rates, name).producers == ("zeek-ecs",)
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


@pytest.mark.parametrize("zeek_success,eve_status", [(True, None), (None, "STATUS_SUCCESS")])
def test_one_sensors_success_never_pairs_with_the_other_sensors_unrecorded_outcome(zeek_success, eve_status):
    # one sensor missed each logon's response: its record is an attempt, the other's the same logon's success
    def zeek_row(n):
        row = zl.NTLM.with_(uid=f"Cntlm{n:010d}", username=f"user{n}", success=True)
        return row if zeek_success else row.without("success")
    zeek = [normalize(zl.WRITERS["plain"](replace(zeek_row(n), ts=zl.T0 + n), f"z{n}")) for n in range(12)]
    eve = [_setup(n, f"user{n}", eve_status) for n in range(12)]
    assert all(match.proposed_lane != "high" for match in rate("NtlmPasswordSpray", zeek + eve))
