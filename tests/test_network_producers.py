"""Only typed producer contracts qualify; session lists never become transactions."""
from datetime import UTC, datetime

import pytest

from romulus.detect.network_producers import protocol_record
from romulus.evidence.typed import FieldValue, TypedEvent


def event(family="smb_tx", producer="zeek-ecs@4", **fields):
    return TypedEvent(id="synthetic", family=family, ts=datetime(2026, 1, 1, tzinfo=UTC), host=None,
                      fields={key: FieldValue(value=value, origin=key) for key, value in fields.items()},
                      raw=[], normalizer=producer)


@pytest.mark.parametrize("producer", ["zeek-ecs@4", "suricata-eve@1"])
@pytest.mark.parametrize("family", ["smb_tx", "rpc_tx", "kerberos_tx", "ntlm_tx", "remote_session", "ldap_tx",
                                     "app_tx", "address_assignment", "dns_query", "http_tx", "tls_session"])
def test_supported_transaction_contracts(producer, family):
    assert protocol_record(event(family, producer), family)


def test_family_is_exact_and_required_fields_are_the_consumers_responsibility():
    assert not protocol_record(event(), "rpc_tx")
    assert protocol_record(event(**{"observer.product": "another sensor label"}), "smb_tx")


@pytest.mark.parametrize("producer", ["lab-ecs@18", "arkime@1", "unknown@1", "zeek-ecs@", "zeek-ecs@4junk",
                                       "suricata-eve@-1", "suricata-eve@0", "zeek-ecs@4@1"])
def test_non_contract_producers_are_rejected(producer):
    assert not protocol_record(event(producer=producer), "smb_tx")


def test_arkime_session_and_lists_never_qualify_as_a_transaction():
    aggregate = event("net_session", "arkime@1", **{"smb.name": ["a", "b"]})
    assert not protocol_record(aggregate, "smb_tx")
    assert not protocol_record(aggregate, "net_session")


@pytest.mark.parametrize("producer", ["zeek-ecs@4", "suricata-eve@1"])
def test_unknown_family_is_not_admitted_by_a_trusted_prefix(producer):
    assert not protocol_record(event("invented_tx", producer), "invented_tx")
