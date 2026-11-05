"""Directory-sync declarations affect replication client evidence, never the RPC target."""
from dataclasses import replace

import pytest

from romulus.detect.windows_rpc import RpcCoercionCall, RpcRemoteAdminCall, RpcReplicationCall
from romulus.evidence.typed import fv
from romulus.evidence.windows import normalize_windows
from romulus.site import absent_site_facts
from tests.test_windows_rpc import DRSR, EFSR, SVCCTL, hit
from tests.windows_process_support import run

SYNC_NOTE = "declared directory-sync host; a compromised sync server is a DCSync path"


def replication(*, host="sync01.example.test", target="10.0.0.10", source=None, code=5, offset=0):
    event = normalize_windows(hit(uuid=DRSR, opnum="3", protocol="1", code=code,
                                  host=host, address=target, offset=offset))
    if source is not None:
        # ETW does not currently supply a client address. A producer that supplies
        # source.ip must establish its source role independently of NetworkAddress.
        event.fields["source.ip"] = fv(source, "source-record:source.ip")
    return event


def evaluate(events, *, cls=RpcReplicationCall, controllers=("dc01.example.test",),
             sync_hosts=(), sync_addresses=()):
    instance = cls()
    instance.site_facts = replace(absent_site_facts(), domain_controllers=controllers,
                                  directory_sync_hosts=sync_hosts,
                                  directory_sync_addresses=sync_addresses)
    try:
        return run(instance, events)
    finally:
        instance.release_state()


@pytest.mark.parametrize("host,declared", [
    ("sync01.example.test", "sync01.example.test"),
    ("SYNC01.EXAMPLE.TEST.", "sync01.example.test"),
    ("sync01.example.test", "sync01"),
    ("sync01", "sync01.example.test"),
])
def test_declared_sync_logging_host_remains_a_replication_lead(host, declared):
    [match] = evaluate([replication(host=host)], sync_hosts=(declared,))
    assert match.proposed_lane == "lead"
    assert SYNC_NOTE in match.notes
    assert "client call to" in match.claim and "was observed" in match.claim


@pytest.mark.parametrize("controllers", [(), ("sync01.example.test",), ("dc01.example.test",)])
def test_sync_declaration_precedes_dc_suppression_and_undeclared_dc_caveat(controllers):
    [match] = evaluate([replication()], controllers=controllers, sync_hosts=("sync01.example.test",))
    assert match.proposed_lane == "lead"
    assert SYNC_NOTE in match.notes
    assert not any("domain controllers not declared" in note for note in match.notes)


@pytest.mark.parametrize("source,declared", [
    ("10.2.3.4", "10.2.3.4"),
    ("10.2.3.4", "10.2.3.0/24"),
    ("2001:db8:1::4", "2001:db8:1::/64"),
    ("::ffff:10.2.3.4", "10.2.3.0/24"),
])
def test_positively_typed_source_address_supports_sync_lead_with_cited_origin(source, declared):
    [match] = evaluate([replication(source=source)], sync_addresses=(declared,))
    assert match.proposed_lane == "lead" and SYNC_NOTE in match.notes
    predicate = next(field for field in match.predicate if field.field == "source.ip")
    assert predicate.value == source and predicate.origin == "source-record:source.ip"


def test_source_address_sync_role_precedes_named_dc_suppression():
    [match] = evaluate([replication(source="10.2.3.4")], controllers=("sync01.example.test",),
                       sync_addresses=("10.2.3.0/24",))
    assert match.proposed_lane == "lead" and SYNC_NOTE in match.notes


@pytest.mark.parametrize("target", ["10.2.3.4", "sync01.example.test"])
def test_rpc_target_address_or_name_cannot_declare_the_client_a_sync_host(target):
    [match] = evaluate([replication(host="workstation.example.test", target=target)],
                       sync_hosts=("sync01.example.test",), sync_addresses=("10.2.3.0/24",))
    assert match.proposed_lane == "high" and SYNC_NOTE not in match.notes


def test_full_client_name_in_another_domain_does_not_match_the_same_short_sync_name():
    event = replication(host="sync01.other.test")
    assert event.host == "sync01"
    [match] = evaluate([event], sync_hosts=("sync01.example.test",))
    assert match.proposed_lane == "high" and SYNC_NOTE not in match.notes


@pytest.mark.parametrize("source", ["10.2.4.4", "not-an-address", 4, ["10.2.3.4"]])
def test_unmatched_or_malformed_source_address_never_lowers_replication(source):
    [match] = evaluate([replication(source=source)], sync_addresses=("10.2.3.0/24",))
    assert match.proposed_lane == "high" and SYNC_NOTE not in match.notes


def test_source_hostname_cannot_override_the_etw_client_logging_host():
    event = replication(host="workstation.example.test")
    event.fields["source.hostname"] = fv("sync01.example.test", "other:source.hostname")
    [match] = evaluate([event], sync_hosts=("sync01.example.test",))
    assert match.proposed_lane == "high"


@pytest.mark.parametrize("controllers,want", [((), "lead"), (("dc01.example.test",), "high"),
                                              (("sync01.example.test",), None)])
def test_unmatched_sync_facts_preserve_existing_dc_behavior(controllers, want):
    found = evaluate([replication()], controllers=controllers, sync_hosts=("unrelated.example.test",),
                     sync_addresses=("10.9.0.0/16",))
    assert len(found) == (want is not None)
    if found:
        assert found[0].proposed_lane == want and SYNC_NOTE not in found[0].notes


def test_server_side_replication_does_not_identify_a_sync_client():
    assert evaluate([replication(code=6, source="10.2.3.4")],
                    sync_hosts=("sync01.example.test",), sync_addresses=("10.2.3.0/24",)) == []


@pytest.mark.parametrize("cls,uuid,opnum,want", [
    (RpcCoercionCall, EFSR, "0", "high"),
    (RpcRemoteAdminCall, SVCCTL, "12", "lead"),
])
def test_sync_declarations_do_not_change_coercion_or_remote_admin_rules(cls, uuid, opnum, want):
    event = normalize_windows(hit(uuid=uuid, opnum=opnum, host="sync01.example.test"))
    event.fields["source.ip"] = fv("10.2.3.4", "source-record:source.ip")
    [match] = evaluate([event], cls=cls, sync_hosts=("sync01.example.test",),
                       sync_addresses=("10.2.3.0/24",))
    assert match.proposed_lane == want
    assert SYNC_NOTE not in match.notes


def test_repeated_sync_client_calls_keep_the_caveat_in_the_bounded_fold():
    events = [replication(source="10.2.3.4", offset=offset) for offset in range(20)]
    [match] = evaluate(events, sync_addresses=("10.2.3.0/24",))
    assert match.proposed_lane == "lead" and SYNC_NOTE in match.notes
    assert "20 RPC call record(s)" in match.claim
    assert len(match.events) <= 16


@pytest.mark.parametrize("reverse", [False, True])
def test_sync_caveat_is_not_lost_when_undeclared_dc_leads_share_the_same_logging_host(reverse):
    events = [replication(source="10.9.3.4", offset=0), replication(source="10.2.3.4", offset=1)]
    if reverse:
        events.reverse()
    found = evaluate(events, controllers=(), sync_addresses=("10.2.3.0/24",))
    assert any(SYNC_NOTE in match.notes for match in found)
    assert all(match.proposed_lane == "lead" for match in found)
