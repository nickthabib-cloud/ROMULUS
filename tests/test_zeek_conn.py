"""Zeek conn records in every shipper shape normalize to one typed net_flow contract.

Fixtures are synthetic records in the published layouts (tests/fixtures/zeek_factory.py names the sources). Equality
across shapes is over everything a rule reads: family, time, sensor, caveats and every typed value; origins differ by
design (each names where its value was read), and a field a shipper never writes is compared among the shapes that
write it (the catalog lists, per shape, where each field is written).
"""
import copy
import json
from dataclasses import replace

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES
from romulus.evidence.zeek import (
    AMBIGUOUS,
    CONTENT_GAP_CAVEAT,
    INTERIM_CAVEAT,
    PARTIAL_CAVEAT,
    ZEEK_DUPLICATE,
    ZEEK_INTERIM_SUPERSEDED,
    ZEEK_NORMALIZER,
    ZeekNotNormalized,
    dotted,
    normalize_plain_zeek,
    plain_record,
    zeek_record,
)
from romulus.evidence.zeek_catalog import CONN, SHAPES, ZEEK_LOGS, lookup_log
from tests.fixtures import zeek_factory as zf

DERIVED_ORIGINS = ("#producer", "#derived:", "#semantics", "#computed:", "#declared", "#present", "#zeek-icmp-type",
                   "#malformed")


def normalize(h, *, sensor=zf.SENSOR, expect_clean=True):
    """One record through the path its shape takes: normalize_hits, or the declared plain-JSON reader."""
    if h["_index"] == zf.INDEX["plain"]:
        return normalize_plain_zeek(h, sensor=sensor)
    events, skips, errors = normalize_hits([h])
    if expect_clean:
        assert (skips, errors) == ({}, []), (skips, errors)
        assert len(events) == 1
    return events[0]


def written_by(shape: str) -> set[str]:
    return {spec.typed for spec in CONN.fields if shape in spec.paths}


def comparable(event, shape: str) -> dict:
    unwritten = {spec.typed for spec in CONN.fields} - written_by(shape)
    return {"family": event.family, "ts": event.ts, "host": event.host, "caveats": event.caveats,
            "normalizer": event.normalizer,
            "fields": {name: value.value for name, value in event.fields.items() if name not in unwritten}}


def assert_same_across_shapes(conn: zf.Conn):
    typed = {shape: normalize(h) for shape, h in zf.in_every_shape(conn).items()}
    views = {shape: comparable(event, shape) for shape, event in typed.items()}
    reference = views["plain"]                          # Zeek's own record: every field it writes
    for shape, view in views.items():
        unwritten = {spec.typed for spec in CONN.fields} - written_by(shape)
        expected = {**reference, "fields": {k: v for k, v in reference["fields"].items() if k not in unwritten}}
        assert view == expected, shape
    return typed


# ---- shape equality --------------------------------------------------------------------------------------------

LOGICAL = {
    "tcp": zf.Conn(), "full": zf.FULL, "udp-dns": zf.UDP_DNS, "icmp-echo": zf.ICMP_ECHO,
    "icmp6-echo": zf.ICMP6_ECHO, "icmp-unreachable": zf.ICMP_UNREACHABLE, "ipv6-tcp": zf.IPV6_TCP,
    "tunnelled": zf.TUNNELLED, "multi-service": zf.MULTI_SERVICE, "removed-service": zf.REMOVED_SERVICE,
    "spicy-service": zf.SPICY_SERVICE, "no-service": replace(zf.Conn(), service=None),
    "no-duration": replace(zf.Conn(), duration=None, orig_bytes=None, resp_bytes=None),
    **{f"state-{state}": zf.conn_in_state(state) for state in zf.CONN_STATES},
    **{f"history-{name}": replace(zf.Conn(), history=history) for name, history in zf.HISTORY_CLASSES.items()},
    "missed-bytes": replace(zf.Conn(), missed_bytes=1460, history="ShADgdFf"),
}


@pytest.mark.parametrize("name", sorted(LOGICAL))
def test_one_logical_conn_types_the_same_in_every_shape(name):
    typed = assert_same_across_shapes(LOGICAL[name])
    for event in typed.values():
        assert event.family == "net_flow" and event.normalizer == ZEEK_NORMALIZER
        assert event.host == zf.SENSOR and event.get("observer.name") == zf.SENSOR
        assert event.get("observer.product") == "zeek" and event.get("zeek.log") == "conn"


def test_every_catalogued_path_is_read_from_its_shape():
    """The full record carries every field: each shape types every field it writes, from one of its own paths."""
    for shape, h in zf.in_every_shape(zf.FULL).items():
        event = normalize(h)
        for spec in CONN.fields:
            if shape not in spec.paths or spec.typed == "conn.interim":
                continue
            assert event.has(spec.typed), (shape, spec.typed)
            origin = event.fields[spec.typed].origin.split(":", 1)[1]
            readable = {path.removesuffix(":ns").removesuffix(":ms").replace("original:", "event.original#original.")
                        for path in spec.paths[shape]}
            assert origin.split("#derived")[0] in readable, (shape, spec.typed, origin)


def test_shipper_variants_type_the_same():
    """Malcolm's text-log values, Filebeat's module field and a shipper that expanded the dotted keys."""
    conn = zf.FULL
    reference = comparable(normalize(zf.malcolm(conn)), "malcolm")
    assert comparable(normalize(zf.malcolm(conn, "mc-text", text=True)), "malcolm") == reference
    assert comparable(normalize(zf.elastic(conn, "fb", filebeat=True)), "elastic") == \
        comparable(normalize(zf.elastic(conn)), "elastic")
    assert comparable(normalize(zf.plain(conn, "pl-x", expanded=True)), "plain") == \
        comparable(normalize(zf.plain(conn)), "plain")


def test_text_values_are_read_only_where_a_shipper_writes_them():
    """Zeek's text form ("900", "T") is Malcolm's for logs it reads as text; elsewhere text is a wrong type."""
    h = zf.plain(zf.Conn(), "pl-text")
    h["_source"]["orig_bytes"] = "1200"
    event = normalize(h)
    assert not event.has("flow.bytes_toserver") and event.get("parse.malformed") == ["orig_bytes"]


# ---- byte counts: payload and IP level are never crossed --------------------------------------------------------

def test_payload_and_ip_bytes_stay_apart_in_every_shape():
    for shape, h in zf.in_every_shape(zf.Conn()).items():
        event = normalize(h)
        assert (event.get("flow.bytes_toserver"), event.get("flow.bytes_toclient")) == (1200, 18000), shape
        assert (event.get("source.bytes"), event.get("destination.bytes")) == (1932, 18832), shape
        assert (event.get("flow.pkts_toserver"), event.get("flow.pkts_toclient")) == (14, 16), shape
        assert event.get("flow.bytes_are_payload") is True


def test_elastic_without_its_original_line_has_no_payload_counts_and_never_substitutes_ip_bytes():
    event = normalize(zf.elastic(zf.Conn(), "el-noorig", original=False))
    assert not event.has("flow.bytes_toserver") and not event.has("flow.bytes_toclient")
    assert event.get("source.bytes") == 1932 and event.get("destination.bytes") == 18832
    assert not event.has("conn.tunnel_parents")


def test_elastic_reads_only_its_removed_fields_from_the_original_line_and_labels_them():
    event = normalize(zf.elastic(zf.TUNNELLED, "el-orig"))
    for name in ("flow.bytes_toserver", "flow.bytes_toclient", "conn.tunnel_parents"):
        assert "#original." in event.fields[name].origin, name
    assert event.get("conn.tunnel_parents") == [zf.PARENT_UID]
    # every other field comes from the document's own structured fields
    others = {n: v.origin for n, v in event.fields.items()
              if n not in ("flow.bytes_toserver", "flow.bytes_toclient", "conn.tunnel_parents")}
    assert not any("event.original" in origin for origin in others.values())


def test_message_is_never_parsed():
    so = zf.security_onion(zf.Conn(), "so-msg")
    line = json.loads(so["_source"]["message"])
    so["_source"]["message"] = json.dumps({**line, "orig_bytes": 999999, "history": "Dd"})
    del so["_source"]["client"]["bytes"]
    event = normalize(so)
    assert not event.has("flow.bytes_toserver") and event.get("conn.history") == "ShADadFf"


# ---- time, duration, sensor, identity ---------------------------------------------------------------------------

def test_start_and_end_come_from_first_packet_and_duration_with_each_shapes_unit():
    for shape, h in zf.in_every_shape(replace(zf.Conn(), duration=7200.000123)).items():
        event = normalize(h)
        assert event.get("flow.start") == "2024-11-18T14:00:00.123000+00:00", shape
        assert event.get("flow.end") == "2024-11-18T16:00:00.123123+00:00", shape
        assert event.get("session.duration_s") == 7200.000123, shape


def test_the_sensor_is_typed_in_each_shapes_order_and_is_the_events_host():
    h = zf.malcolm(zf.Conn())
    h["_source"]["host"]["name"] = "beat-host"
    assert normalize(h).host == zf.SENSOR                    # Malcolm: node first
    el = zf.elastic(zf.Conn())
    assert normalize(el).host == zf.SENSOR                   # Elastic: agent.name before host.name
    del el["_source"]["agent"]
    assert normalize(el).host == f"{zf.SENSOR}-shipper"
    assert normalize(zf.plain(zf.Conn()), sensor=None).host is None    # plain: only a declaration names it
    assert "net_flow" in NETWORK_OBSERVER_FAMILIES
    assert ("host", zf.SENSOR, "observer") in normalize(zf.malcolm(zf.Conn())).entities()


def test_uid_is_typed_and_the_event_id_is_the_records_logical_identity():
    a = normalize(zf.malcolm(zf.Conn(), "copy-a"))
    b = normalize({**zf.malcolm(zf.Conn(), "copy-b"), "_index": "arkime_sessions3-other"})
    assert a.get("zeek.uid") == zf.UID and a.id == b.id and a.raw != b.raw
    other_sensor = normalize(zf.malcolm(zf.Conn(), "copy-c", sensor="sensor-zeek-02"))
    assert other_sensor.id != a.id


def test_double_shipped_copies_merge_their_raw_refs():
    hits = [zf.malcolm(zf.Conn(), "copy-a"), {**zf.malcolm(zf.Conn(), "copy-b"), "_index": "arkime_sessions3-x"}]
    events, skips, errors = normalize_hits(hits)
    assert errors == [] and skips == {ZEEK_DUPLICATE: 1} and len(events) == 1
    assert sorted(r.native_id for r in events[0].raw) == ["copy-a", "copy-b"]


def test_different_records_sharing_a_uid_stay_separate():
    events, skips, errors = normalize_hits([zf.malcolm(zf.Conn(), "a"),
                                            zf.malcolm(replace(zf.Conn(), orig_bytes=5), "b")])
    assert (skips, errors) == ({}, []) and len(events) == 2 and events[0].id != events[1].id


def test_a_record_without_a_uid_is_its_own_identity():
    h = zf.plain(zf.Conn())
    del h["_source"]["uid"]
    event = normalize(h)
    assert not event.has("zeek.uid") and [r.native_id for r in event.raw] == ["pl-1"]


def test_community_id_written_by_the_shipper_stays_written_and_is_computed_only_when_absent():
    for shape, h in zf.in_every_shape(zf.Conn()).items():
        event = normalize(h)
        assert "#computed" not in event.fields["network.community_id"].origin, shape
    event = normalize(zf.plain(replace(zf.Conn(), community=None)))
    assert event.get("network.community_id") == zf.Conn().community_id
    assert event.fields["network.community_id"].origin.endswith("#computed:community_id_v1")
    assert not normalize(zf.plain(replace(zf.ICMP_ECHO, community=None))).has("network.community_id")


# ---- TCP opener, history caveats, services, tunnels ---------------------------------------------------------------

@pytest.mark.parametrize("history,opened", [("ShADadFf", True), ("S", True), ("^hADadfF", None), ("DdAa", None),
                                            ("HhAa", None), ("Sh^ADa", None)])
def test_the_originator_opened_only_when_its_syn_was_the_first_packet_and_zeek_did_not_flip(history, opened):
    assert normalize(zf.malcolm(replace(zf.Conn(), history=history))).get("tcp.opened_by_orig") is opened
    assert normalize(zf.malcolm(replace(zf.UDP_DNS, history="S"))).get("tcp.opened_by_orig") is None


def test_truncation_is_a_caveat_on_the_record():
    gap = normalize(zf.malcolm(replace(zf.Conn(), missed_bytes=1460, history="ShADgdFf")))
    assert any(c.startswith("Zeek missed 1460 bytes") for c in gap.caveats) and CONTENT_GAP_CAVEAT in gap.caveats
    assert PARTIAL_CAVEAT in normalize(zf.malcolm(replace(zf.Conn(), history="ShADadxFf"))).caveats
    assert PARTIAL_CAVEAT in normalize(zf.malcolm(replace(zf.Conn(), history="ShADadXFf"))).caveats
    assert normalize(zf.malcolm(zf.Conn())).caveats == []


def test_services_are_typed_as_a_list_and_one_service_is_the_application_protocol():
    multi = normalize(zf.malcolm(zf.MULTI_SERVICE))
    assert multi.get("network.protocols") == ["gssapi", "smb", "krb", "dce_rpc", "ntlm"]
    assert not multi.has("network.app_proto")                 # several confirmed: none is picked
    removed = normalize(zf.elastic(zf.REMOVED_SERVICE))
    assert removed.get("network.protocols") == ["http"] and removed.get("network.protocols_removed") == ["ssl"]
    assert removed.get("network.app_proto") == "http"
    assert normalize(zf.plain(zf.SPICY_SERVICE)).get("network.protocols") == ["krb"]
    assert not normalize(zf.security_onion(replace(zf.Conn(), service=None))).has("network.protocols")


def test_tunnel_parents_are_a_typed_list():
    for shape, h in zf.in_every_shape(zf.TUNNELLED).items():
        assert normalize(h).get("conn.tunnel_parents") == [zf.PARENT_UID], shape


# ---- ICMP keeps the type/counterpart semantics ---------------------------------------------------------------

@pytest.mark.parametrize("conn,transport,icmp_type,ports", [
    (zf.ICMP_ECHO, "icmp", 8, (8, 0)),
    (zf.ICMP6_ECHO, "ipv6-icmp", 128, (128, 129)),
    (zf.ICMP_UNREACHABLE, "icmp", 3, (3, 1)),
])
def test_icmp_type_comes_from_the_originator_port_and_the_counterpart_is_never_the_code(conn, transport, icmp_type,
                                                                                          ports):
    for shape, h in zf.in_every_shape(conn).items():
        event = normalize(h)
        assert event.get("network.transport") == transport, shape
        assert event.get("icmp.type") == icmp_type and not event.has("icmp.code"), shape
        assert (event.get("source.port"), event.get("destination.port")) == ports, shape


def test_elastic_icmp_reads_the_ports_it_moved():
    event = normalize(zf.elastic(zf.ICMP_ECHO))
    assert event.fields["icmp.type"].origin == "el-1:zeek.connection.icmp.type#zeek-icmp-type"
    assert event.fields["destination.port"].origin == "el-1:zeek.connection.icmp.code"


# Migrated from the ICMP-only normalizer's tests: the same input gives the same typed values.

def test_zeek_icmp_connection_uses_documented_type_code_ports_and_types_flow_counters():
    typed = normalize(zf.legacy_zeek_icmp())
    assert typed.family == "net_flow" and typed.get("observer.product") == "zeek"
    assert typed.get("icmp.type") == 8 and typed.get("icmp.code") is None
    assert typed.get("flow.bytes_toserver") == 900 and typed.get("flow.bytes_toclient") == 4000
    assert typed.get("flow.pkts_toserver") == 9 and typed.get("flow.pkts_toclient") == 8
    assert typed.get("session.duration_s") == 2.0 and typed.host == "zeek1"


def test_zeek_icmp_absent_type_and_code_stay_absent():
    typed = normalize(zf.legacy_zeek_icmp(source_port=None, destination_port=None))
    assert typed.get("icmp.type") is None and typed.get("icmp.code") is None


def test_zeek_icmp_counterpart_port_is_not_code_and_ipv6_is_typed_from_addresses():
    timestamp = normalize(zf.legacy_zeek_icmp("timestamp", source_port=13, destination_port=14))
    assert timestamp.get("icmp.type") == 13 and timestamp.get("icmp.code") is None
    reply_first = normalize(zf.legacy_zeek_icmp("reply", source_port=0, destination_port=8))
    assert reply_first.get("icmp.type") == 0 and reply_first.get("icmp.code") is None
    typed_v6 = normalize(zf.legacy_zeek_icmp("v6", source_port=128, destination_port=129, source_ip="fd00::5",
                                             destination_ip="2001:db8::50"))
    assert typed_v6.get("network.transport") == "ipv6-icmp"
    assert typed_v6.get("icmp.type") == 128 and typed_v6.get("icmp.code") is None


# ---- Malcolm specifics ---------------------------------------------------------------------------------------------

def test_malcolm_root_id_on_a_zeek_row_is_never_an_arkime_continuation():
    h = zf.malcolm(zf.Conn(), "mc-root")
    assert h["_source"]["rootId"] == zf.UID and "firstPacket" in h["_source"]
    event = normalize(h)
    assert event.family == "net_flow" and not any(name.startswith("arkime.") for name in event.fields)


def test_interim_rows_are_typed_and_superseded_by_the_final_record():
    final = replace(zf.Conn(), uid="Clong", duration=7200.0)
    early = replace(final, duration=600.0, orig_bytes=100, resp_bytes=200)
    later = replace(final, duration=3600.0, orig_bytes=600, resp_bytes=900)
    interim = normalize(zf.malcolm(early, "i1", interim=True))
    assert interim.get("conn.interim") is True and INTERIM_CAVEAT in interim.caveats
    events, skips, errors = normalize_hits([zf.malcolm(early, "i1", interim=True), zf.malcolm(final, "f"),
                                            zf.malcolm(later, "i2", interim=True)])
    assert errors == [] and skips == {ZEEK_INTERIM_SUPERSEDED: 2}
    assert [e.raw[0].native_id for e in events] == ["f"]
    events, skips, _ = normalize_hits([zf.malcolm(early, "i1", interim=True), zf.malcolm(later, "i2", interim=True)])
    assert skips == {ZEEK_INTERIM_SUPERSEDED: 1} and [e.raw[0].native_id for e in events] == ["i2"]
    plain_interim = normalize_plain_zeek(zf.plain(early, path="conn_long"), sensor=zf.SENSOR)
    assert plain_interim.get("conn.interim") is True


def test_malcolm_missing_timestamp_tag_is_a_caveat():
    h = zf.malcolm(zf.Conn())
    h["_source"]["tags"] = ["_missing_timestamp"]
    assert any("ingested" in c for c in normalize(h).caveats)


def test_a_malcolm_mixed_batch_routes_each_row_to_its_own_normalizer():
    events, skips, errors = normalize_hits(zf.malcolm_mixed_batch())
    assert errors == [] and skips == {ZEEK_INTERIM_SUPERSEDED: 1}
    by_id = {e.raw[0].native_id: e for e in events}
    assert sorted(by_id) == ["malcolm-suricata-flow", "mx-arkime", "mx-arkime-provider", "mx-zeek-final",
                             "mx-zeek-icmp", "mx-zeek-tcp"]
    for nid in ("mx-zeek-tcp", "mx-zeek-icmp", "mx-zeek-final"):
        assert (by_id[nid].family, by_id[nid].normalizer) == ("net_flow", ZEEK_NORMALIZER)
    assert by_id["mx-arkime"].family == "net_session" and by_id["mx-arkime"].get("arkime.continuation") is False
    assert by_id["mx-arkime-provider"].family == "net_session"
    assert by_id["malcolm-suricata-flow"].normalizer.startswith("lab-ecs@")


# ---- recognition and dispatch ------------------------------------------------------------------------------------

def test_recognition_reads_only_shipper_written_fields_and_one_record_matches_one_shape():
    assert zeek_record(zf.malcolm(zf.Conn())["_source"]).shape == "malcolm"
    assert zeek_record(zf.elastic(zf.Conn())["_source"]).shape == "elastic"
    assert zeek_record(zf.elastic(zf.Conn(), filebeat=True)["_source"]).shape == "elastic"
    assert zeek_record(zf.security_onion(zf.Conn())["_source"]).shape == "security_onion"
    assert zeek_record(zf.security_onion(zf.Conn(), bare=True)["_source"]).shape == "security_onion"
    # Security Onion's indexed dataset is zeek.<log>, like Elastic's: its agent's one data stream "zeek" and the module
    # tell it apart; an Elastic Agent document's data stream is zeek.<stream> itself
    so_real = zf.security_onion(zf.Conn())["_source"]
    assert so_real["event"]["dataset"] == "zeek.conn" and so_real["data_stream"]["dataset"] == "zeek"
    # without Security Onion's markers zeek.conn is no shipper's known layout: never read (Elastic's is zeek.connection)
    for sparse in ({**so_real, "data_stream": {"dataset": "zeek.connection"}},
                   {**so_real, "event": {**so_real["event"], "module": None}}):
        assert zeek_record(sparse).shape == AMBIGUOUS and zeek_record(sparse).log is None
    filebeat = zf.elastic(zf.Conn(), filebeat=True)["_source"]
    assert "data_stream" not in filebeat and zeek_record(filebeat).shape == "elastic"
    assert zeek_record(zf.plain(zf.Conn())["_source"]) is None            # nothing the shipper wrote says Zeek
    suricata = zf.previous_shapes()["malcolm-suricata-flow"][0]["_source"]
    assert zeek_record({**suricata, "event": {**suricata["event"], "module": "zeek"}}) is None   # provider decides
    assert zeek_record({"event": {"dataset": "conn"}}) is None                    # a bare name alone is not Zeek
    assert zeek_record({"message": json.dumps(zf.zeek_json(zf.Conn()))}) is None  # nor is content
    # a zeek.* dataset is Elastic's whatever provider a record names; Malcolm writes bare log names only
    elastic = zf.elastic(zf.Conn())["_source"]
    assert zeek_record({**elastic, "event": {**elastic["event"], "provider": "zeek"}}).shape == "elastic"
    # Malcolm's notice rows carry event.module "zeek" too: the provider makes them Malcolm's
    malcolm = zf.malcolm(zf.Conn())["_source"]
    assert zeek_record({**malcolm, "event": {**malcolm["event"], "module": "zeek"}}).shape == "malcolm"
    # a dotted dataset that is not zeek.* is no Zeek log name: the record keeps the path it took before
    so = zf.security_onion(zf.Conn())["_source"]
    assert zeek_record({**so, "event": {**so["event"], "dataset": "suricata.eve.alert"}}) is None
    assert zeek_record({**malcolm, "event": {**malcolm["event"], "dataset": "suricata.eve.flow"}}) is None


def test_every_catalogued_log_has_a_fixture_in_every_shape():
    """Gate: a log added to the catalog needs a logical fixture written in every shape that normalizes to it. A shape
    may be left out only when the catalog says why (its shipper publishes no pipeline for the log), and then the
    fixture factory writes no record of the log in that shape either."""
    assert set(zf.SHAPES) == set(SHAPES)
    for log in ZEEK_LOGS:
        assert log.name in zf.LOG_FIXTURES, f"no fixture for catalogued Zeek log {log.name}"
        declared = set(log.names) | set(log.absent_shapes)
        assert declared == set(SHAPES), f"{log.name}: a shape is neither catalogued nor declared absent"
        assert not set(log.names) & set(log.absent_shapes), log.name
        assert all(reason for reason in log.absent_shapes.values()), log.name
        written = zf.in_every_shape(zf.LOG_FIXTURES[log.name])
        assert set(written) == set(log.names), f"{log.name}: fixture shapes {sorted(written)}"
        for shape, h in written.items():
            event = normalize(h)
            assert (event.family, event.get("zeek.log")) == (log.family, log.name), shape


def test_uncatalogued_logs_are_skips_the_sweep_counts_as_unevaluated_never_errors():
    """Every uncatalogued log in every shape is also in the dispatch golden, compared with what it was before."""
    malcolm = zf.malcolm(zf.Conn())
    malcolm["_source"]["event"]["dataset"] = "kerberos"
    elastic = zf.elastic(zf.Conn())
    elastic["_source"]["event"]["dataset"] = elastic["_source"]["data_stream"]["dataset"] = "zeek.kerberos"
    so = zf.security_onion(zf.Conn())
    so["_source"]["event"]["dataset"] = "zeek.kerberos"
    bare = zf.security_onion(zf.Conn(), "so-bare", bare=True)
    bare["_source"]["event"]["dataset"] = "kerberos"
    listed = zf.malcolm(zf.Conn(), "listed")
    listed["_source"]["event"]["dataset"] = ["smb_files", "smb_cmd"]
    events, skips, errors = normalize_hits([malcolm, elastic, so, bare, listed])
    assert events == [] and errors == []
    assert skips == {"dataset:kerberos is not normalized": 2, "dataset:zeek.kerberos is not normalized": 2,
                     "dataset:['smb_files', 'smb_cmd'] is not normalized": 1}
    with pytest.raises(ZeekNotNormalized, match=r"^dataset:kerberos is not normalized$"):
        normalize_plain_zeek(zf.plain(zf.Conn(), path="kerberos"))


def test_errors_are_tagged_with_the_dispatch_token():
    h = zf.malcolm(zf.Conn(), "bad")
    del h["_source"]["@timestamp"], h["_source"]["firstPacket"]
    _, _, errors = normalize_hits([h])
    assert errors == [("bad", "zeek:conn: zeek conn record has no first-packet time")]


@pytest.mark.parametrize("name,h,outcome", zf.malformed_rows(), ids=[r[0] for r in zf.malformed_rows()])
def test_malformed_rows_are_errors_skips_or_listed_fields_never_crashes(name, h, outcome):
    if h["_index"] == zf.INDEX["plain"]:
        try:
            events, skips, errors = [normalize_plain_zeek(h, sensor=zf.SENSOR)], {}, []
        except (ValueError, TypeError) as e:
            events, skips, errors = [], {}, [(h["_id"], str(e))]
    else:
        events, skips, errors = normalize_hits([h])
    if outcome == "error":
        assert events == [] and skips == {} and len(errors) == 1
    elif outcome == "skip":
        assert events == [] and errors == [] and sum(skips.values()) == 1
    elif outcome == "absent":
        assert errors == [] and len(events) == 1 and not events[0].has("parse.malformed")
        assert not events[0].has("conn.history") and not events[0].has("conn.tunnel_parents")
    elif outcome == "not-zeek":
        assert zeek_record(h["_source"]) is None and errors == []
        assert events and not any(e.normalizer == ZEEK_NORMALIZER for e in events)
    else:
        assert errors == [] and len(events) == 1
        assert outcome in events[0].get("parse.malformed"), events[0].get("parse.malformed")
        assert events[0].has("network.transport")                  # the rest of the record is kept


@pytest.mark.parametrize("name,h", zf.overflow_rows(), ids=[r[0] for r in zf.overflow_rows()])
def test_an_end_or_duration_beyond_any_time_is_listed_and_flow_end_left_out(name, h):
    if h["_index"] == zf.INDEX["plain"]:
        events, skips, errors = [normalize_plain_zeek(h, sensor=zf.SENSOR)], {}, []
    else:
        events, skips, errors = normalize_hits([h])
    assert (skips, errors) == ({}, []) and len(events) == 1
    event = events[0]
    assert not event.has("flow.end")
    malformed = event.get("parse.malformed")
    assert malformed and any("duration" in path for path in malformed), malformed
    assert event.has("flow.start") and event.has("source.ip")       # the rest of the record is kept


def test_an_integer_beyond_zeeks_count_type_is_malformed():
    h = zf.plain(zf.Conn())
    h["_source"]["orig_bytes"] = 2**64
    event = normalize(h)
    assert not event.has("flow.bytes_toserver") and event.get("parse.malformed") == ["orig_bytes"]


def test_a_numeric_timestamp_in_an_index_document_is_epoch_milliseconds():
    h = zf.elastic(zf.Conn())
    h["_source"]["@timestamp"] = round(zf.T0 * 1000)
    assert normalize(h).get("flow.start") == "2024-11-18T14:00:00.123000+00:00"


def test_plain_json_takes_its_log_from_path_or_the_declaration_never_from_content():
    h = zf.plain(zf.Conn(), path=None)
    assert plain_record(h["_source"], "conn").log is CONN
    with pytest.raises(ValueError, match="names no log"):
        normalize_plain_zeek(h)
    with pytest.raises(ValueError, match="different log"):
        plain_record(zf.plain(zf.Conn(), path="conn")["_source"], "dns")
    assert lookup_log("plain", "conn_long") is CONN and lookup_log("malcolm", "conn_long") is None


def test_dotted_reader_finds_literal_nested_and_mixed_keys():
    src = {"id.orig_h": "10.0.0.5", "id": {"resp_h": "10.0.0.6"}, "zeek": {"conn.history": "S", "conn": {"x": 1}},
           "a": {"b.c": {"d": 4}}}
    assert dotted(src, "id.orig_h") == "10.0.0.5" and dotted(src, "id.resp_h") == "10.0.0.6"
    assert dotted(src, "zeek.conn.history") == "S" and dotted(src, "zeek.conn.x") == 1
    assert dotted(src, "a.b.c.d") == 4 and dotted(src, "a.b") is dotted(src, "missing")


# ---- secrets -----------------------------------------------------------------------------------------------------

SECRET = "Hunter2-synthetic-secret"


def test_no_password_value_reaches_a_typed_event_error_or_skip():
    malcolm = zf.malcolm(replace(zf.Conn(), uid="Cpw1"), "pw-malcolm")
    malcolm["_source"]["related"] = {"password": [SECRET], "user": ["alice"]}
    malcolm["_source"]["url"] = {"password": SECRET}
    plain = zf.plain(replace(zf.Conn(), uid="Cpw2"), "pw-plain")
    plain["_source"]["password"] = SECRET
    conn = replace(zf.Conn(), uid="Cpw3")
    elastic = zf.elastic(conn, "pw-elastic")
    elastic["_source"]["zeek"]["connection"]["password"] = SECRET
    elastic["_source"]["event"]["original"] = json.dumps({**zf.zeek_json(conn), "password": SECRET})
    broken = copy.deepcopy(malcolm)
    broken["_id"] = "pw-broken"
    broken["_source"]["@timestamp"] = SECRET
    events, skips, errors = normalize_hits([malcolm, elastic, broken])
    events.append(normalize_plain_zeek(plain, sensor=zf.SENSOR))
    assert len(events) == 3 and len(errors) == 1
    for event in events:
        assert event.get("auth.cleartext_credentials_present") is True
        assert SECRET not in event.model_dump_json()
    assert SECRET not in json.dumps([skips, errors])
    clean = normalize(zf.malcolm(zf.Conn()))
    assert not clean.has("auth.cleartext_credentials_present")
