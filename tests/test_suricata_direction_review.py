"""Application roles never rewrite Suricata's packet-oriented tuple."""
import copy

import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_elastic_suricata import shipped
from tests.test_malcolm_suricata import _malcolm_base, filebeat_hit, malcolm_hit
from tests.test_suricata_protocols import BASE


SHAPES = ["original", "message", "filebeat", "agent", "malcolm"]


def directed_hit(protocol, block, shape, *, source="10.0.0.10", sport=3389,
                 destination="10.0.0.5", dport=51000, transport="TCP"):
    eve = {**BASE, "src_ip": source, "src_port": sport, "dest_ip": destination, "dest_port": dport,
           "proto": transport, "event_type": protocol, protocol: copy.deepcopy(block)}
    if shape in {"filebeat", "agent"}:
        return shipped(eve, shape, "direction")
    if shape == "malcolm":
        return malcolm_hit(_malcolm_base(protocol, eve["timestamp"], {protocol: eve[protocol]},
            source={"ip": source, "port": sport}, destination={"ip": destination, "port": dport},
            network={"transport": transport.casefold(), "protocol": [protocol]}), "direction")
    result = filebeat_hit(eve, "direction")
    if shape == "message":
        result["_source"]["message"] = result["_source"]["event"].pop("original")
    return result


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("subtype", ["initial_request", "initial_response", "connect_request",
                                    "connect_response", "tls_handshake"])
def test_rdp_subtype_and_packet_direction_survive_each_shape(shape, subtype):
    client = subtype in {"initial_request", "connect_request"}
    source, destination = ("10.0.0.5", "10.0.0.10") if client else ("10.0.0.10", "10.0.0.5")
    sport, dport = (51000, 3389) if client else (3389, 51000)
    events, skips, errors = normalize_hits([directed_hit("rdp", {"event_type": subtype}, shape,
        source=source, destination=destination, sport=sport, dport=dport)])
    assert not skips and not errors and len(events) == 1
    event = events[0]
    assert event.get("rdp.message") == subtype
    assert "rdp.event_type" in event.fields["rdp.message"].origin
    assert (event.get("source.ip"), event.get("source.port")) == (source, sport)
    assert (event.get("destination.ip"), event.get("destination.port")) == (destination, dport)
