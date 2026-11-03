"""Suricata records as Malcolm indexes them normalize to the typed event of the same EVE record read from Filebeat.

The Malcolm fixtures are synthetic values in the layout Malcolm's Logstash pipeline writes (cisagov/Malcolm,
Apache-2.0, commit c6160d8e3101c017a45df9d40504ece3da047f43): logstash/pipelines/suricata/11_suricata_logs.conf
(EVE parsed into `suricata.*`; the 5-tuple, transport, community id and event type moved to ECS fields; the alert's
signature and id moved to rule.name and rule.id and its category to the head of rule.category; MITRE technique ids
split into threat.technique.id and .subtechnique.id; tls.version and the JA3/JA3S hashes moved under tls.*;
app_proto at the head of network.protocol), 12_suricata_normalize.conf (copies only), 13_suricata_convert.conf
(timestamp, flow.start/end and tls.notbefore/notafter rewritten as ISO times), enrichment/96_make_unique.conf
(network.protocol de-duplicated, "failed" removed, dcerpc/ftp-data/krb5 renamed) and enrichment/98_finalize.conf
(`message` removed). No upstream file is copied.

Equality is over everything a rule reads: family, time, sensor and every typed value. Origins differ by design (each
names where its value was read), times inside typed values compare as instants (Malcolm rewrites their text), and
alert.mitre_technique_id compares as a set (Malcolm keeps the ids, not their order).
"""
import copy
import json
from datetime import datetime

import pytest

from romulus.evidence.normalize import (
    MALCOLM_FTP_CAVEAT,
    MALCOLM_MISSING_TIMESTAMP_CAVEAT,
    MALCOLM_NO_APP_PROTO_CAVEAT,
    MALCOLM_PARSE_FAILED_CAVEAT,
    normalize_hits,
    normalize_malcolm_suricata,
    normalize_suricata,
)

SENSOR = "sensor-01"
COMMUNITY = "1:c3ludGhldGljLWNvbW11bml0eT0="
FLOW_ID = 1234567890123456
TIME_FIELDS = {"flow.start", "flow.end"}
SET_FIELDS = {"alert.mitre_technique_id"}

TUPLE_EVE = {"src_ip": "10.0.0.5", "src_port": 51000, "dest_ip": "203.0.113.10", "dest_port": 443, "proto": "TCP"}
TUPLE_MALCOLM = {"source": {"ip": "10.0.0.5", "port": 51000}, "destination": {"ip": "203.0.113.10", "port": 443}}

HTTP_BLOCK = {"hostname": "www.example.test", "url": "/index.html", "http_user_agent": "ExampleAgent/1.0",
              "http_content_type": "text/html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200,
              "length": 1024}

EVE = {
    "alert": {
        "timestamp": "2024-11-18T14:00:00.123000+0000", "flow_id": FLOW_ID, "in_iface": "eth1", "event_type": "alert",
        **TUPLE_EVE, "dest_port": 80, "pkt_src": "wire/pcap", "community_id": COMMUNITY, "tx_id": 0,
        "alert": {"action": "allowed", "gid": 1, "signature_id": 2000001, "rev": 3,
                  "signature": "ET INFO Example Test Signature", "category": "Potentially Bad Traffic", "severity": 2,
                  "metadata": {"signature_severity": ["Informational"], "mitre_tactic_id": ["TA0011"],
                               "mitre_tactic_name": ["Command_And_Control"], "mitre_technique_id": ["T1071.001"],
                               "mitre_technique_name": ["Web_Protocols"], "former_category": ["INFO"]}},
        "http": HTTP_BLOCK, "app_proto": "http", "direction": "to_server",
        "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "bytes_toserver": 300, "bytes_toclient": 200,
                 "start": "2024-11-18T13:59:59.500000+0000"},
    },
    "flow": {
        "timestamp": "2024-11-18T14:00:05.000000+0000", "flow_id": FLOW_ID, "event_type": "flow", **TUPLE_EVE,
        "app_proto": "tls", "community_id": COMMUNITY,
        "flow": {"pkts_toserver": 12, "pkts_toclient": 10, "bytes_toserver": 2400, "bytes_toclient": 18000,
                 "start": "2024-11-18T14:00:00.000000+0000", "end": "2024-11-18T14:00:04.250000+0000", "age": 4,
                 "state": "closed", "reason": "timeout", "alerted": False},
        "tcp": {"tcp_flags": "1b", "tcp_flags_ts": "1b", "tcp_flags_tc": "1b", "syn": True, "fin": True, "psh": True,
                "ack": True, "state": "closed"},
    },
    "netflow": {
        "timestamp": "2024-11-18T14:00:05.000000+0000", "flow_id": FLOW_ID, "event_type": "netflow",
        "src_ip": "10.0.0.5", "src_port": 53000, "dest_ip": "198.51.100.53", "dest_port": 53, "proto": "UDP",
        "app_proto": "dns",
        "netflow": {"pkts": 1, "bytes": 74, "start": "2024-11-18T14:00:00.000000+0000",
                    "end": "2024-11-18T14:00:00.000000+0000", "age": 0, "min_ttl": 64, "max_ttl": 64},
    },
    "dns": {
        "timestamp": "2024-11-18T14:00:00.250000+0000", "flow_id": FLOW_ID, "event_type": "dns",
        "src_ip": "10.0.0.5", "src_port": 53000, "dest_ip": "198.51.100.53", "dest_port": 53, "proto": "UDP",
        "dns": {"version": 2, "type": "answer", "id": 4660, "flags": "8180", "qr": True, "rd": True, "ra": True,
                "opcode": 0, "rrname": "www.example.test", "rrtype": "A", "rcode": "NOERROR",
                "answers": [{"rrname": "www.example.test", "rrtype": "A", "ttl": 300, "rdata": "203.0.113.20"}],
                "grouped": {"A": ["203.0.113.20"]}},
    },
    "http": {
        "timestamp": "2024-11-18T14:00:00.300000+0000", "flow_id": FLOW_ID, "event_type": "http", **TUPLE_EVE,
        "dest_port": 80, "tx_id": 0, "http": HTTP_BLOCK,
    },
    "fileinfo": {
        "timestamp": "2024-11-18T14:00:00.400000+0000", "flow_id": FLOW_ID, "event_type": "fileinfo", **TUPLE_EVE,
        "dest_port": 80, "app_proto": "http", "http": HTTP_BLOCK,
        "fileinfo": {"filename": "/files/report.pdf", "sid": [], "gaps": False, "state": "CLOSED", "stored": False,
                     "size": 2048, "tx_id": 0, "magic": "PDF document, version 1.7"},
    },
    "tls": {
        "timestamp": "2024-11-18T14:00:00.500000+0000", "flow_id": FLOW_ID, "event_type": "tls", **TUPLE_EVE,
        "tls": {"subject": "CN=www.example.test", "issuerdn": "C=US, O=Example CA, CN=Example Issuing CA",
                "serial": "01:02:03:04", "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
                "sni": "www.example.test", "version": "TLS 1.2", "notbefore": "2024-01-01T00:00:00",
                "notafter": "2025-01-01T00:00:00",
                "ja3": {"hash": "e7d705a3286e19ea42f587b344ee6865", "string": "771,4866-4867,0-23,29-23,0"},
                "ja3s": {"hash": "f4febc55ea12b31ae17cfb7e614afda8", "string": "771,4866,43-51"},
                "ja4": "t13d1516h2_8daaf6152771_02713d6af862"},
    },
    "ssh": {
        "timestamp": "2024-11-18T14:00:00.600000+0000", "flow_id": FLOW_ID, "event_type": "ssh", **TUPLE_EVE,
        "dest_port": 22,
        "ssh": {"client": {"proto_version": "2.0", "software_version": "OpenSSH_9.6",
                           "hassh": {"hash": "ec7378c1a92f5a8dde7e8b7a1ddf33d1", "string": "curve25519-sha256"}},
                "server": {"proto_version": "2.0", "software_version": "OpenSSH_8.9p1",
                           "hassh": {"hash": "b12d2871a1189eff20364cf5333619ee", "string": "curve25519-sha256"}}},
    },
}


def _malcolm_base(dataset: str, timestamp: str, suricata: dict, **top) -> dict:
    return {"@timestamp": timestamp, "event": {"provider": "suricata", "dataset": dataset, "kind": "event"},
            "host": {"name": SENSOR}, "node": SENSOR, "timestamp": 1731938400123, "firstPacket": 1731938400000,
            "lastPacket": 1731938400000, "suricata": {"timestamp": timestamp, "flow_id": FLOW_ID, **suricata}, **top}


MALCOLM = {
    "alert": _malcolm_base(
        "alert", "2024-11-18T14:00:00.123Z",
        {"in_iface": "eth1", "tx_id": 0, "http": HTTP_BLOCK,
         "alert": {"action": "allowed", "rev": 3, "severity": 2, "metadata": {"signature_severity": ["Informational"]}},
         "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "bytes_toserver": 300, "bytes_toclient": 200,
                  "start": "2024-11-18T13:59:59.500Z"}},
        **{**TUPLE_MALCOLM, "destination": {"ip": "203.0.113.10", "port": 80}},
        network={"transport": "tcp", "protocol": ["http"], "community_id": COMMUNITY, "type": "ipv4"},
        rule={"name": "ET INFO Example Test Signature", "id": 2000001,
              "category": ["Potentially Bad Traffic", "Command and Control"]},
        threat={"framework": "MITRE ATT&CK", "tactic": {"id": ["TA0011"], "name": ["Command and Control"]},
                "technique": {"id": ["T1071"], "name": ["Application Layer Protocol"],
                              "subtechnique": {"id": ["T1071.001"], "name": ["Web Protocols"]}}},
        client={"bytes": 300, "packets": 3}, server={"bytes": 200, "packets": 2}, rootId=FLOW_ID),
    "flow": _malcolm_base(
        "flow", "2024-11-18T14:00:05.000Z",
        {"flow": {"pkts_toserver": 12, "pkts_toclient": 10, "bytes_toserver": 2400, "bytes_toclient": 18000,
                  "start": "2024-11-18T14:00:00.000Z", "end": "2024-11-18T14:00:04.250Z", "age": 4,
                  "state": "closed", "reason": "timeout", "alerted": False},
         "tcp": {"tcp_flags": "1b", "tcp_flags_ts": "1b", "tcp_flags_tc": "1b", "syn": True, "fin": True,
                 "psh": True, "ack": True, "state": "closed"}},
        **TUPLE_MALCOLM, network={"transport": "tcp", "protocol": ["tls"], "community_id": COMMUNITY}),
    "netflow": _malcolm_base(
        "netflow", "2024-11-18T14:00:05.000Z",
        {"netflow": {"pkts": 1, "bytes": 74, "start": "2024-11-18T14:00:00.000000+0000",
                     "end": "2024-11-18T14:00:00.000000+0000", "age": 0, "min_ttl": 64, "max_ttl": 64}},
        source={"ip": "10.0.0.5", "port": 53000}, destination={"ip": "198.51.100.53", "port": 53},
        network={"transport": "udp", "protocol": ["dns"]}),
    "dns": _malcolm_base(
        "dns", "2024-11-18T14:00:00.250Z",
        {"dns": copy.deepcopy(EVE["dns"]["dns"])},
        source={"ip": "10.0.0.5", "port": 53000}, destination={"ip": "198.51.100.53", "port": 53},
        network={"transport": "udp", "protocol": ["dns"]}),
    "http": _malcolm_base(
        "http", "2024-11-18T14:00:00.300Z", {"tx_id": 0, "http": HTTP_BLOCK},
        **{**TUPLE_MALCOLM, "destination": {"ip": "203.0.113.10", "port": 80}},
        network={"transport": "tcp", "protocol": ["http"], "protocol_version": ["1.1"]}),
    "fileinfo": _malcolm_base(
        "fileinfo", "2024-11-18T14:00:00.400Z",
        {"http": HTTP_BLOCK, "fileinfo": {"filename": "/files/report.pdf", "sid": [], "gaps": False,
                                          "state": "CLOSED", "size": 2048, "tx_id": 0,
                                          "magic": "PDF document, version 1.7"}},
        **{**TUPLE_MALCOLM, "destination": {"ip": "203.0.113.10", "port": 80}},
        network={"transport": "tcp", "protocol": ["http"]},
        file={"path": ["/files/report.pdf"], "size": [2048], "mime_type": ["PDF document, version 1.7"],
              "source": ["http"]}),
    "tls": _malcolm_base(
        "tls", "2024-11-18T14:00:00.500Z",
        {"tls": {"subject": "CN=www.example.test", "issuerdn": "C=US, O=Example CA, CN=Example Issuing CA",
                 "serial": "01:02:03:04",
                 "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
                 "sni": "www.example.test", "notbefore": "2024-01-01T00:00:00.000Z",
                 "notafter": "2025-01-01T00:00:00.000Z", "ja3": {}, "ja3s": {},
                 "ja4": "t13d1516h2_8daaf6152771_02713d6af862"}},
        **TUPLE_MALCOLM, network={"transport": "tcp", "protocol": ["tls"]},
        tls={"version": "TLS 1.2", "client": {"ja3": "e7d705a3286e19ea42f587b344ee6865"},
             "server": {"ja3s": "f4febc55ea12b31ae17cfb7e614afda8"}}),
    "ssh": _malcolm_base(
        "ssh", "2024-11-18T14:00:00.600Z", {"ssh": copy.deepcopy(EVE["ssh"]["ssh"])},
        **{**TUPLE_MALCOLM, "destination": {"ip": "203.0.113.10", "port": 22}},
        network={"transport": "tcp", "protocol": ["ssh"]}),
}


def filebeat_hit(eve: dict, nid: str = "fb-1") -> dict:
    return {"_index": "logs-suricata.eve-default", "_id": nid,
            "_source": {"@timestamp": "2024-11-18T14:00:10.000Z", "host": {"name": SENSOR},
                        "event": {"dataset": "suricata.eve", "module": "suricata", "original": json.dumps(eve)}}}


def malcolm_hit(src: dict, nid: str = "mc-1") -> dict:
    return {"_index": "arkime_sessions3-241118", "_id": nid, "_source": src}


def comparable(event) -> dict:
    fields = {}
    for name, value in event.fields.items():
        v = value.value
        if name in TIME_FIELDS:
            parsed = datetime.fromisoformat(v)
            v = parsed.timestamp() if parsed.tzinfo else parsed.isoformat()
        elif name in SET_FIELDS:
            v = sorted(v)
        fields[name] = v
    return {"family": event.family, "ts": event.ts, "host": event.host, "fields": fields}


@pytest.mark.parametrize("event_type", sorted(EVE))
def test_malcolm_record_types_the_same_as_its_filebeat_eve_twin(event_type):
    filebeat = normalize_suricata(filebeat_hit(EVE[event_type]))
    malcolm = normalize_malcolm_suricata(malcolm_hit(copy.deepcopy(MALCOLM[event_type])))
    assert comparable(malcolm) == comparable(filebeat)
    assert malcolm.caveats == filebeat.caveats == []
    # every value is cited where Malcolm put it, never as an EVE line it does not keep
    assert all(not v.origin.startswith("mc-1:event.original") for v in malcolm.fields.values())


def test_moved_fields_cite_the_malcolm_paths():
    alert = normalize_malcolm_suricata(malcolm_hit(copy.deepcopy(MALCOLM["alert"])))
    origins = {name: value.origin for name, value in alert.fields.items()}
    assert origins["source.ip"] == "mc-1:source.ip" and origins["destination.port"] == "mc-1:destination.port"
    assert origins["network.transport"] == "mc-1:network.transport"
    assert origins["network.community_id"] == "mc-1:network.community_id"
    assert origins["network.app_proto"] == "mc-1:network.protocol#derived:app_proto"
    assert origins["alert.signature"] == "mc-1:rule.name" and origins["alert.signature_id"] == "mc-1:rule.id"
    assert origins["alert.category"] == "mc-1:rule.category#derived:first-value"
    assert origins["alert.mitre_technique_id"].startswith("mc-1:threat.technique.subtechnique.id+threat.technique.id")
    assert origins["alert.severity"] == "mc-1:suricata.alert.severity"
    assert origins["suricata.flow_id"] == "mc-1:suricata.flow_id"
    assert origins["http.hostname"] == "mc-1:suricata.http.hostname"
    tls = normalize_malcolm_suricata(malcolm_hit(copy.deepcopy(MALCOLM["tls"])))
    origins = {name: value.origin for name, value in tls.fields.items()}
    assert origins["tls.version"] == "mc-1:tls.version" and origins["tls.ja3"] == "mc-1:tls.client.ja3"
    assert origins["tls.ja3s"] == "mc-1:tls.server.ja3s" and origins["tls.ja4"] == "mc-1:suricata.tls.ja4"
    assert origins["tls.client.server_name"] == "mc-1:suricata.tls.sni"
    netflow = normalize_malcolm_suricata(malcolm_hit(copy.deepcopy(MALCOLM["netflow"])))
    assert netflow.fields["flow.bytes"].origin == "mc-1:suricata.netflow.bytes"


def test_alert_technique_ids_keep_a_bare_parent_but_not_an_implied_one():
    src = copy.deepcopy(MALCOLM["alert"])
    src["threat"]["technique"] = {"id": ["T1071", "T1105"], "subtechnique": {"id": ["T1071.001"]}}
    event = normalize_malcolm_suricata(malcolm_hit(src))
    assert event.get("alert.mitre_technique_id") == ["T1071.001", "T1105"]


def test_written_and_computed_community_ids_agree():
    eve = {k: v for k, v in EVE["flow"].items() if k != "community_id"}
    src = copy.deepcopy(MALCOLM["flow"])
    del src["network"]["community_id"]
    filebeat, malcolm = normalize_suricata(filebeat_hit(eve)), normalize_malcolm_suricata(malcolm_hit(src))
    assert malcolm.get("network.community_id") == filebeat.get("network.community_id") is not None
    assert malcolm.fields["network.community_id"].origin.endswith("network.transport#computed:community_id_v1")


# ---- app_proto read back from network.protocol -----------------------------------------------------------------

def _flow(**changes):
    eve = {**copy.deepcopy(EVE["flow"]), **changes.pop("eve", {})}
    for key in changes.pop("eve_drop", ()):
        eve.pop(key, None)
    src = copy.deepcopy(MALCOLM["flow"])
    src["network"]["protocol"] = changes.pop("protocol")
    if src["network"]["protocol"] is None:
        del src["network"]["protocol"]
    src["suricata"].update(changes.pop("suricata", {}))
    return normalize_suricata(filebeat_hit(eve)), normalize_malcolm_suricata(malcolm_hit(src))


@pytest.mark.parametrize("app_proto,stored", [("dcerpc", ["dce_rpc"]), ("krb5", ["krb"]), ("smb", ["smb"]),
                                              ("http2", ["http2"])])
def test_app_proto_is_read_back_including_malcolm_renames_of_one_protocol(app_proto, stored):
    filebeat, malcolm = _flow(eve={"app_proto": app_proto}, protocol=stored)
    assert malcolm.get("network.app_proto") == filebeat.get("network.app_proto") == app_proto
    assert malcolm.caveats == []


@pytest.mark.parametrize("app_proto", ["ftp", "ftp-data"])
def test_ftp_and_ftp_data_cannot_be_told_apart_and_are_not_typed(app_proto):
    _filebeat, malcolm = _flow(eve={"app_proto": app_proto}, protocol=["ftp"])
    assert not malcolm.has("network.app_proto") and malcolm.caveats == [MALCOLM_FTP_CAVEAT]


def test_failed_detection_is_removed_by_malcolm_and_the_record_says_so():
    filebeat, malcolm = _flow(eve={"app_proto": "failed"}, protocol=None)
    assert filebeat.get("network.app_proto") == "failed"
    assert not malcolm.has("network.app_proto") and malcolm.caveats == [MALCOLM_NO_APP_PROTO_CAVEAT]


def test_no_app_proto_at_all_is_typed_as_none_with_the_caveat():
    filebeat, malcolm = _flow(eve_drop=["app_proto"], protocol=None)
    assert not filebeat.has("network.app_proto") and not malcolm.has("network.app_proto")
    assert malcolm.caveats == [MALCOLM_NO_APP_PROTO_CAVEAT]


def test_a_direction_protocol_without_app_proto_is_not_taken_for_app_proto():
    filebeat, malcolm = _flow(eve={"app_proto_tc": "tls"}, eve_drop=["app_proto"], protocol=["tls"],
                              suricata={"app_proto_tc": "tls"})
    assert not filebeat.has("network.app_proto") and not malcolm.has("network.app_proto")
    assert malcolm.caveats == [MALCOLM_NO_APP_PROTO_CAVEAT]


def test_app_proto_with_later_direction_values_is_the_first_value():
    filebeat, malcolm = _flow(eve={"app_proto": "http", "app_proto_ts": "failed"}, protocol=["http"],
                              suricata={"app_proto_ts": "failed"})
    assert malcolm.get("network.app_proto") == filebeat.get("network.app_proto") == "http"


def test_icmp_inferred_by_malcolm_is_not_an_application_protocol():
    eve = {**copy.deepcopy(EVE["flow"]), "proto": "ICMP", "icmp_type": 8, "icmp_code": 0}
    for key in ("app_proto", "src_port", "dest_port", "tcp"):
        eve.pop(key)
    src = copy.deepcopy(MALCOLM["flow"])
    src["network"] = {"transport": "icmp", "protocol": ["icmp"], "community_id": COMMUNITY}
    src["source"].pop("port")
    src["destination"].pop("port")
    src["suricata"].update({"icmp_type": 8, "icmp_code": 0})
    src["suricata"].pop("tcp")
    filebeat, malcolm = normalize_suricata(filebeat_hit(eve)), normalize_malcolm_suricata(malcolm_hit(src))
    assert comparable(malcolm) == comparable(filebeat) and malcolm.caveats == []
    assert malcolm.get("icmp.type") == 8 and not malcolm.has("network.app_proto")


def test_app_layer_records_never_type_the_name_malcolm_inferred():
    for event_type in ("dns", "http", "tls", "ssh"):
        event = normalize_malcolm_suricata(malcolm_hit(copy.deepcopy(MALCOLM[event_type])))
        assert not event.has("network.app_proto") and event.caveats == []


# ---- Malcolm's own marks ---------------------------------------------------------------------------------------

def test_parse_failure_and_missing_timestamp_tags_become_caveats():
    src = copy.deepcopy(MALCOLM["alert"])
    src["tags"] = ["_filebeat_suricata", "proto_parse_failed", "client_stream_failed", "_missing_timestamp"]
    src["suricata"].pop("http")
    event = normalize_malcolm_suricata(malcolm_hit(src))
    assert MALCOLM_PARSE_FAILED_CAVEAT in event.caveats and MALCOLM_MISSING_TIMESTAMP_CAVEAT in event.caveats
    assert not event.has("http.hostname")


def test_the_sensor_falls_back_to_malcolm_node():
    src = copy.deepcopy(MALCOLM["flow"])
    del src["host"]
    src["node"] = "malcolm-upload"
    assert normalize_malcolm_suricata(malcolm_hit(src)).host == "malcolm-upload"


def test_a_record_still_carrying_its_eve_line_is_read_from_it():
    src = copy.deepcopy(MALCOLM["flow"])
    src["message"] = json.dumps(EVE["flow"])
    event = normalize_malcolm_suricata(malcolm_hit(src))
    assert comparable(event) == comparable(normalize_suricata(filebeat_hit(EVE["flow"])))
    assert event.fields["source.ip"].origin == "mc-1:event.original#eve.src_ip"


# ---- dispatch and malformed rows ---------------------------------------------------------------------------------

def test_dispatch_routes_malcolm_rows_and_leaves_the_filebeat_path_alone():
    filebeat = filebeat_hit(EVE["flow"], "fb-1")
    filebeat["_source"]["event"]["provider"] = "suricata"          # a Filebeat row naming a provider stays EVE
    hits = [filebeat, malcolm_hit(copy.deepcopy(MALCOLM["flow"]), "mc-1"),
            malcolm_hit(copy.deepcopy(MALCOLM["alert"]), "mc-2")]
    events, skips, errors = normalize_hits(hits)
    assert (skips, errors) == ({}, [])
    assert [e.fields["source.ip"].origin for e in events] == ["fb-1:event.original#eve.src_ip", "mc-1:source.ip",
                                                              "mc-2:source.ip"]
    assert [e.family for e in events] == ["net_flow", "net_flow", "net_alert"]


def _malformed(mutate) -> tuple:
    src = copy.deepcopy(MALCOLM["alert"])
    mutate(src)
    return normalize_hits([malcolm_hit(src, "bad")])


@pytest.mark.parametrize("mutate,error", [
    (lambda s: s.pop("suricata"), "no suricata object"),
    (lambda s: s["event"].update(dataset=["alert", "flow"]), "not one event type"),
    (lambda s: s["event"].pop("dataset"), "not one event type"),
    (lambda s: s["suricata"].update(tls="not an object"), "tls block is str"),
    (lambda s: s["suricata"].update(alert=["not", "an", "object"]), "'list' object has no attribute 'get'"),
    (lambda s: (s.pop("@timestamp"), s["suricata"].pop("timestamp")), "@timestamp"),
])
def test_unreadable_malcolm_rows_are_errors_never_crashes(mutate, error):
    events, skips, errors = _malformed(mutate)
    assert events == [] and skips == {} and len(errors) == 1
    assert errors[0][0] == "bad" and error in errors[0][1]


@pytest.mark.parametrize("mutate,path,absent", [
    (lambda s: s["network"].update(protocol=[5]), "network.protocol", "network.app_proto"),
    (lambda s: s["rule"].update(category={"name": "x"}), "rule.category", "alert.category"),
    (lambda s: s["threat"]["technique"].update(id=7), "threat.technique.id", None),
])
def test_wrongly_typed_malcolm_fields_are_listed_and_dropped_while_the_record_is_kept(mutate, path, absent):
    events, skips, errors = _malformed(mutate)
    assert errors == [] and skips == {} and len(events) == 1
    event = events[0]
    assert path in event.get("parse.malformed")
    if absent:
        assert not event.has(absent)
    assert event.get("alert.signature") == "ET INFO Example Test Signature"


def test_an_event_type_the_eve_normalizer_skips_is_skipped_for_malcolm_too():
    src = _malcolm_base("stats", "2024-11-18T14:00:00.000Z", {"stats": {"uptime": 10}}, tags=["_suricatastats"])
    events, skips, errors = normalize_hits([malcolm_hit(src)])
    assert events == [] and errors == [] and skips == {"suricata event_type 'stats' is not normalized": 1}
