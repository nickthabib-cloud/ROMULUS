"""Suricata records shipped by Filebeat's suricata module or the Elastic Agent Suricata integration, without their EVE
line, normalize to the typed event of the same EVE record read from the line.

The two shippers' documents are built here by applying, in Python, the moves their pipelines make (Filebeat
x-pack/filebeat/module/suricata/eve config/eve.yml and ingest/*.yml, identical on 7.17, 8.19 and main; Elastic
integrations packages/suricata 2.27.1 data_stream/eve/elasticsearch/ingest_pipeline/*.yml). Values are synthetic;
no upstream file is copied. Equality is over everything a rule reads: family, time, sensor and every typed value.
Origins differ by design; flow times compare as instants (the pipelines rewrite them to the millisecond).
"""
import copy
import html
import json
from datetime import UTC, datetime

import pytest

from romulus.evidence.community import community_id
from romulus.evidence.normalize import (
    ELASTIC_ACTION_CAVEAT,
    ELASTIC_DN_CAVEAT,
    ELASTIC_ESCAPED_CAVEAT,
    ELASTIC_GROUPED_CAVEAT,
    ELASTIC_NO_APP_PROTO_CAVEAT,
    ELASTIC_RECONSTRUCTED_CAVEAT,
    ELASTIC_SNI_CAVEAT,
    elastic_suricata_eve,
    normalize_hits,
    normalize_suricata,
)
from romulus.hunt import sweep as sw
from romulus.sources.compile import _pred
from romulus.sources.models import Predicate
from romulus.sources.profile import contract_from_types
from tests.test_malcolm_suricata import EVE, SENSOR, comparable, filebeat_hit

FILEBEAT, AGENT = "filebeat", "agent"
SHAPES = (FILEBEAT, AGENT)


def _ms(text: str) -> str:
    when = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f%z") if "." in text else datetime.fromisoformat(text)
    return when.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _put(doc: dict, path: str, value) -> None:
    parts = path.split(".")
    for part in parts[:-1]:
        doc = doc.setdefault(part, {})
    doc[parts[-1]] = value


def _pop(doc: dict, path: str):
    parts = path.split(".")
    for part in parts[:-1]:
        doc = doc.get(part)
        if not isinstance(doc, dict):
            return None
    return doc.pop(parts[-1], None)


def _append(doc: dict, path: str, value) -> None:
    parts = path.split(".")
    for part in parts[:-1]:
        doc = doc.setdefault(part, {})
    current = doc.get(parts[-1])
    doc[parts[-1]] = ([] if current is None else current if isinstance(current, list) else [current]) + [value]


_PROTOCOL = {"dns": "dns", "ftp": "ftp", "ftp_data": "ftp", "http": "http", "http2": "http", "smb": "smb",
             "ssh": "ssh", "tls": "tls", "rdp": "rdp", "rfb": "rdp", "tftp": "tftp", "mqtt": "mqtt"}


def shipped(eve: dict, shape: str, nid: str = "es-1") -> dict:
    """The document the shipper indexes for one EVE record, without the line."""
    template = html.escape if shape == FILEBEAT else (lambda text: text)     # double- or triple-brace templates
    s = copy.deepcopy(eve)
    doc: dict = {"host": {"name": SENSOR}, "suricata": {"eve": s},
                 "event": {"dataset": "suricata.eve", "module": "suricata", "kind": "event", "category": ["network"]}}
    if shape == AGENT:
        doc["data_stream"] = {"dataset": "suricata.eve", "type": "logs", "namespace": "default"}
    else:
        doc.update({"fileset": {"name": "eve"}, "input": {"type": "log"}, "service": {"type": "suricata"}})
    # the 5-tuple, transport and flow id (Beats processors, or the Agent's first ingest processors)
    for key, path in (("src_ip", "source.address"), ("src_port", "source.port"), ("dest_ip", "destination.address"),
                      ("dest_port", "destination.port"), ("proto", "network.transport")):
        if key in s:
            _put(doc, path, s.pop(key))
    for address, ip in (("source.address", "source.ip"), ("destination.address", "destination.ip")):
        if address.split(".")[0] in doc and "address" in doc[address.split(".")[0]]:
            _put(doc, ip, doc[address.split(".")[0]]["address"])
    if "flow_id" in s:
        s["flow_id"] = str(s["flow_id"])
    doc["@timestamp"] = _ms(s.pop("timestamp"))
    doc["network"] = doc.get("network", {})
    doc["network"]["community_id"] = community_id(
        doc.get("source", {}).get("ip"), doc.get("source", {}).get("port"), doc.get("destination", {}).get("ip"),
        doc.get("destination", {}).get("port"), doc["network"].get("transport"))
    et = s["event_type"]
    if et in _PROTOCOL:
        doc["network"]["protocol"] = _PROTOCOL[et]
    if et == "http":
        doc["event"]["type"] = ["access", "protocol"]
    elif et in ("dns", "ssh", "tls"):
        doc["event"]["type"] = ["protocol"]
    elif et == "flow":
        doc["event"]["type"] = ["connection"]
    app = s.get("app_proto")
    if isinstance(app, str):
        s["app_proto"] = app = app.lower()
        if app not in ("failed", "template", "template-rust"):
            doc["network"]["protocol"] = app
    protocol = doc["network"].get("protocol")
    d = s.get("dns")
    if protocol == "dns" and isinstance(d, dict):
        for key, path in (("id", "dns.id"), ("rcode", "dns.response_code"), ("type", "dns.type")):
            if d.get(key) not in (None, ""):
                _put(doc, path, template(str(d[key])))
        if d.get("type") == "answer" and d.get("version") is None:
            answer = {k: d[n] for k, n in (("name", "rrname"), ("data", "rdata"), ("type", "rrtype"), ("ttl", "ttl"))
                      if d.get(n) is not None}
            if answer:
                _put(doc, "dns.answers", [answer])
        if d.get("type") == "answer" and d.get("version") == 2 and "answers" in d:
            _put(doc, "dns.answers", [{({"rrname": "name", "rrtype": "type", "rdata": "data"}).get(k, k): v
                                       for k, v in item.items()} for item in d.pop("answers")])
        for key in ("aa", "tc", "rd", "ra", "qr", "version", "flags", "grouped"):
            d.pop(key, None)
    t = s.get("tls")
    if protocol == "tls" and isinstance(t, dict):
        if isinstance(t.get("sni"), str) and t["sni"].endswith("."):
            t["sni"] = t["sni"][:-1]
        for key, path, gsub in (("subject", "tls.server.subject", shape == FILEBEAT),
                                ("issuerdn", "tls.server.issuer", True)):
            if t.get(key):
                _put(doc, path, template(t[key]))
                if gsub:
                    t[key] = t[key].replace("\\,", "")
        if t.get("sni"):
            _put(doc, "tls.client.server_name", template(t["sni"]))
            _put(doc, "destination.domain", template(t["sni"]))
    h = s.get("http")
    if isinstance(h, dict) and (shape == AGENT or protocol == "http"):
        if "http_method" in h:
            _put(doc, "http.request.method", template(h["http_method"]))
        if "status" in h:
            _put(doc, "http.response.status_code", h.pop("status"))
        if "hostname" in h:
            host = h.pop("hostname")
            if shape == AGENT:
                _append(doc, "destination.domain", host)
            else:
                _put(doc, "destination.domain", host)
        for key, path in (("url", "url.original"), ("http_refer", "http.request.referrer"),
                          ("length", "http.response.body.bytes")):
            if key in h:
                _put(doc, path, h.pop(key))
        if "http_user_agent" in h:
            _put(doc, "user_agent.original", h["http_user_agent"])
    flow = s.get("flow")
    if isinstance(flow, dict) and flow.get("state") in ("new", "closed"):
        _append(doc, "event.type", "start" if flow["state"] == "new" else "end")
    fi = s.get("fileinfo")
    if isinstance(fi, dict):
        for key, path in (("filename", "file.path"), ("size", "file.size")):
            if key in fi:
                _put(doc, path, fi.pop(key))
    a = s.get("alert")
    if isinstance(a, dict):
        if a.get("category") is not None:
            doc["message"] = str(a["category"])
            _put(doc, "rule.category", template(str(a["category"])))
        for key, path in (("signature_id", "rule.id"), ("signature", "rule.name")):
            if a.get(key) not in (None, ""):
                _put(doc, path, template(str(a[key])))
        if "action" in a:
            _append(doc, "event.type", {"blocked": "denied"}.get(a["action"], a["action"]))
            a.pop("action")
        if "severity" in a:
            _put(doc, "event.severity", a.pop("severity"))
        md = a.get("metadata") or {}
        for key in ("protocols", "attack_target", "malware", "cve", "classtype", "priority"):
            if key in md:
                a[key] = md.pop(key)
        for key, path in (("mitre_tactic_id", "threat.tactic.id"), ("mitre_tactic_name", "threat.tactic.name"),
                          ("mitre_technique_id", "threat.technique.id")):
            if key in md:
                _put(doc, path, md.pop(key))
    if isinstance(flow, dict):
        for key, path in (("pkts_toclient", "destination.packets"), ("pkts_toserver", "source.packets"),
                          ("bytes_toclient", "destination.bytes"), ("bytes_toserver", "source.bytes")):
            if key in flow:
                _put(doc, path, flow.pop(key))
        for key, path in (("start", "event.start"), ("end", "event.end")):
            if key in flow:
                _put(doc, path, _ms(flow[key]))
    if doc["network"].get("transport"):
        doc["network"]["transport"] = doc["network"]["transport"].lower()
    for path in ("suricata.eve.app_proto", "suricata.eve.flow.end", "suricata.eve.flow.start",
                 "suricata.eve.http.http_method", "suricata.eve.http.http_user_agent"):
        _pop(doc, path)
    if shape == AGENT:
        for path in ("suricata.eve.src_port", "suricata.eve.dest_port"):
            _pop(doc, path)
        if a is not None and not a.get("metadata"):
            a.pop("metadata", None)
    return {"_index": f"{shape}-suricata", "_id": nid, "_source": doc}


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("event_type", sorted(EVE))
def test_shipped_record_types_the_same_as_its_eve_line(event_type, shape):
    line = normalize_suricata(filebeat_hit(EVE[event_type]))
    doc = shipped(EVE[event_type], shape)
    rebuilt = normalize_suricata(doc)
    assert comparable(rebuilt) == comparable(line)
    assert rebuilt.caveats[0] == ELASTIC_RECONSTRUCTED_CAVEAT
    assert set(rebuilt.caveats) <= {ELASTIC_RECONSTRUCTED_CAVEAT, ELASTIC_SNI_CAVEAT}
    # every value is cited where the shipper put it, never as a line it did not keep
    assert all(not v.origin.startswith("es-1:event.original") for v in rebuilt.fields.values())


def test_moved_fields_cite_their_indexed_paths():
    alert = normalize_suricata(shipped(EVE["alert"], AGENT))
    origins = {name: value.origin for name, value in alert.fields.items()}
    assert origins["source.ip"] == "es-1:source.address" and origins["destination.port"] == "es-1:destination.port"
    assert origins["network.transport"] == "es-1:network.transport"
    assert origins["network.app_proto"] == "es-1:network.protocol"
    assert origins["alert.signature"] == "es-1:suricata.eve.alert.signature"
    assert origins["alert.severity"] == "es-1:event.severity"
    assert origins["alert.action"] == "es-1:event.type#derived:alert.action"
    assert origins["alert.mitre_technique_id"] == "es-1:threat.technique.id"
    assert origins["flow.bytes_toserver"] == "es-1:source.bytes" and origins["flow.start"] == "es-1:event.start"
    assert origins["suricata.flow_id"] == "es-1:suricata.eve.flow_id#derived:integer"
    assert origins["http.hostname"] == "es-1:destination.domain"
    assert origins["user_agent.original"] == "es-1:user_agent.original"
    assert origins["network.community_id"] == "es-1:suricata.eve.community_id"
    dns = normalize_suricata(shipped(EVE["dns"], FILEBEAT))
    assert dns.fields["dns.answers"].origin == "es-1:dns.answers"
    assert dns.fields["dns.version"].origin.startswith("es-1:suricata.eve.dns.type#derived:version")
    file = normalize_suricata(shipped(EVE["fileinfo"], FILEBEAT))
    assert file.fields["file.name"].origin == "es-1:file.path"


def test_a_document_still_carrying_its_line_is_read_from_the_line():
    doc = shipped(EVE["flow"], FILEBEAT)
    doc["_source"]["event"]["original"] = json.dumps(EVE["flow"])
    event = normalize_suricata(doc)
    assert event.fields["source.ip"].origin == "es-1:event.original#eve.src_ip" and event.caveats == []


def test_the_category_in_message_is_not_taken_for_a_line():
    doc = shipped(EVE["alert"], AGENT)
    assert doc["_source"]["message"] == "Potentially Bad Traffic"
    assert normalize_suricata(doc).caveats[0] == ELASTIC_RECONSTRUCTED_CAVEAT


def test_dispatch_reads_the_agent_dataset_field_and_counts_event_types():
    doc = shipped(EVE["tls"], AGENT)
    del doc["_source"]["event"]["dataset"]
    shapes: dict = {}
    events, skips, errors = normalize_hits([doc, shipped(EVE["alert"], FILEBEAT, "es-2")], shapes=shapes)
    assert (skips, errors) == ({}, []) and [e.family for e in events] == ["tls_session", "net_alert"]
    assert shapes == {"suricata.eve.elastic:tls": 1, "suricata.eve.elastic:alert": 1}


def test_failed_app_proto_is_dropped_by_the_shipper_and_the_record_says_so():
    eve = {**copy.deepcopy(EVE["flow"]), "app_proto": "failed"}
    event = normalize_suricata(shipped(eve, FILEBEAT))
    assert not event.has("network.app_proto") and ELASTIC_NO_APP_PROTO_CAVEAT in event.caveats
    ftp = normalize_suricata(shipped({**copy.deepcopy(EVE["flow"]), "app_proto": "ftp-data"}, AGENT))
    assert ftp.get("network.app_proto") == "ftp-data"


def test_blocked_alerts_read_back_from_event_type():
    eve = copy.deepcopy(EVE["alert"])
    eve["alert"]["action"] = "blocked"
    eve["flow"]["state"] = "new"
    event = normalize_suricata(shipped(eve, FILEBEAT))
    assert event.get("alert.action") == "blocked"
    doc = shipped(EVE["alert"], AGENT)
    doc["_source"]["event"]["type"] = ["allowed", "denied"]
    event = normalize_suricata(doc)
    assert not event.has("alert.action") and ELASTIC_ACTION_CAVEAT in event.caveats


def test_values_a_double_brace_template_may_have_escaped_are_not_guessed():
    eve = copy.deepcopy(EVE["http"])
    eve["http"]["http_method"] = "GET&X"
    event = normalize_suricata(shipped(eve, FILEBEAT))
    assert not event.has("http.request.method")
    assert any(c.startswith(ELASTIC_ESCAPED_CAVEAT) and "http.request.method" in c for c in event.caveats)
    # the Agent copies the method: what it indexed is the value, but '&' cannot be told from an escape either way
    assert event.get("url.original") == "/index.html"


@pytest.mark.parametrize("shape", SHAPES)
def test_certificate_names_with_an_escaped_comma_are_read_exactly_or_not_at_all(shape):
    eve = copy.deepcopy(EVE["tls"])
    eve["tls"]["subject"] = "C=US, O=Acme\\, Inc., CN=www.example.test"
    eve["tls"]["issuerdn"] = "C=US, O=R&D\\, Ltd., CN=Example CA"
    line = normalize_suricata(filebeat_hit(eve))
    event = normalize_suricata(shipped(eve, shape))
    assert event.get("tls.server.subject_cn") == line.get("tls.server.subject_cn") == ["www.example.test"]
    certificate = event.get("tls.server.certificates")[0]
    assert certificate["subject_dn"] == eve["tls"]["subject"]
    # the issuer lost "\," in place and its copy holds "&", which a double-brace template may have escaped (Filebeat
    # does; this Agent package does not, but earlier ones did): not typed
    assert certificate["issuer_dn"] is None
    assert ELASTIC_DN_CAVEAT + "tls.issuerdn" in event.caveats
    eve["tls"]["issuerdn"] = "C=US, O=Example\\, Ltd., CN=Example CA"
    certificate = normalize_suricata(shipped(eve, shape)).get("tls.server.certificates")[0]
    assert certificate["issuer_dn"] == eve["tls"]["issuerdn"]


def test_dns_layouts_read_back_their_version():
    v1 = {"timestamp": "2024-11-18T14:00:00.250000+0000", "flow_id": 1, "event_type": "dns", "src_ip": "10.0.0.5",
          "src_port": 53000, "dest_ip": "198.51.100.53", "dest_port": 53, "proto": "UDP",
          "dns": {"type": "answer", "id": 1, "rrname": "a.example.test", "rrtype": "CNAME", "ttl": 30,
                  "rdata": "b.example.test"}}
    query = {**v1, "dns": {"type": "query", "id": 1, "rrname": "a.example.test", "rrtype": "A", "tx_id": 0}}
    v3 = {**v1, "dns": {"version": 3, "type": "response", "id": 1, "rcode": "NOERROR",
                        "queries": [{"rrname": "a.example.test", "rrtype": "A"}],
                        "answers": [{"rrname": "a.example.test", "rrtype": "A", "ttl": 5, "rdata": "192.0.2.1"}]}}
    nx = {**v1, "dns": {"version": 2, "type": "answer", "id": 1, "rrname": "a.example.test", "rrtype": "A",
                        "rcode": "NXDOMAIN", "flags": "8183"}}
    for eve in (v1, query, v3, nx):
        for shape in SHAPES:
            line, rebuilt = normalize_suricata(filebeat_hit(eve)), normalize_suricata(shipped(eve, shape))
            assert comparable(rebuilt) == comparable(line), (eve["dns"], shape)
    grouped_only = {**v1, "dns": {"version": 2, "type": "answer", "id": 1, "rrname": "a.example.test",
                                  "rrtype": "A", "rcode": "NOERROR", "grouped": {"A": ["192.0.2.1"]}}}
    line, rebuilt = normalize_suricata(filebeat_hit(grouped_only)), normalize_suricata(shipped(grouped_only, AGENT))
    assert line.has("dns.answers") and not rebuilt.has("dns.answers")
    assert ELASTIC_GROUPED_CAVEAT in rebuilt.caveats and rebuilt.get("dns.version") == 2


def test_written_and_computed_community_ids_agree():
    eve = {k: v for k, v in EVE["flow"].items() if k != "community_id"}
    line, rebuilt = normalize_suricata(filebeat_hit(eve)), normalize_suricata(shipped(eve, FILEBEAT))
    assert rebuilt.get("network.community_id") == line.get("network.community_id") is not None
    assert rebuilt.fields["network.community_id"].origin == (
        "es-1:source.address+source.port+destination.address+destination.port+network.transport"
        "#computed:community_id_v1")


@pytest.mark.parametrize("mutate,error", [
    (lambda s: s["error"].update(message=["Processor 'date' failed"]), "pipeline failed"),
    (lambda s: s["suricata"]["eve"].update(tls="not an object"), "tls block is str"),
    (lambda s: s.pop("@timestamp"), "@timestamp"),
])
def test_unreadable_shipped_records_are_errors_tagged_with_the_dataset(mutate, error):
    doc = shipped(EVE["tls"], AGENT, "bad")
    doc["_source"]["error"] = {}
    mutate(doc["_source"])
    if not doc["_source"]["error"]:
        del doc["_source"]["error"]
    events, skips, errors = normalize_hits([doc])
    assert events == [] and skips == {} and len(errors) == 1
    assert error in errors[0][1] and sw._error_tag(errors[0][1]) == "suricata.eve"
    assert sw.DATASET_FAMILIES["suricata.eve"] == sw.NET_FAMILIES


def test_an_event_type_the_eve_normalizer_skips_is_skipped_here_too():
    doc = shipped({"timestamp": "2024-11-18T14:00:00.000000+0000", "event_type": "stats", "stats": {"uptime": 1}},
                  FILEBEAT)
    events, skips, errors = normalize_hits([doc])
    assert events == [] and errors == [] and skips == {"suricata event_type 'stats' is not normalized": 1}


def test_rebuild_returns_the_eve_record_and_its_origins():
    eve, origins, caveats, malformed = elastic_suricata_eve(shipped(EVE["flow"], FILEBEAT)["_source"], "x")
    assert eve["src_ip"] == "10.0.0.5" and eve["flow"]["bytes_toclient"] == 18000 and eve["flow_id"] == 1234567890123456
    assert origins["source.ip"] == "x:source.address" and malformed == [] and caveats == [ELASTIC_RECONSTRUCTED_CAVEAT]


def test_per_type_dataset_predicates_also_select_the_elastic_documents_of_those_types():
    types = {"@timestamp": "date", "event.dataset": "keyword", "source.ip": "ip", "destination.ip": "ip"}
    predicate = Predicate(field="event.dataset", op="in", value=["suricata.eve.alert", "suricata.eve.dns", "zeek.conn"])
    plain = contract_from_types("t", types, role="network")
    assert _pred(predicate, plain) == {"terms": {"event.dataset": predicate.value}}       # unchanged without the field
    shipped_contract = contract_from_types("t", {**types, "data_stream.dataset": "constant_keyword",
                                                 "suricata.eve.event_type": "keyword"}, role="network")
    assert _pred(predicate, shipped_contract) == {"bool": {"should": [
        {"terms": {"event.dataset": predicate.value}},
        {"bool": {"filter": [
            {"bool": {"should": [{"term": {"event.dataset": "suricata.eve"}},
                                 {"term": {"data_stream.dataset": "suricata.eve"}}], "minimum_should_match": 1}},
            {"terms": {"suricata.eve.event_type": ["alert", "dns"]}}]}}], "minimum_should_match": 1}}
    other = Predicate(field="event.dataset", op="eq", value="zeek.conn")
    assert _pred(other, shipped_contract) == {"term": {"event.dataset": "zeek.conn"}}


def test_the_network_sweep_reaches_the_shipped_dataset_and_counts_its_families():
    from datetime import UTC, datetime

    from romulus.sources.models import Window
    from tests.test_sweep import _repo

    profile = {"role": "network", "datasets": {"suricata.eve": 1000, "zeek.not_a_catalogued_log": 5}, "notes": []}
    assert sw.delivered_families(profile, None) == frozenset(sw.NET_FAMILIES)
    contract = contract_from_types("t", {"@timestamp": "date", "event.dataset": "keyword", "source.ip": "ip",
                                         "destination.ip": "ip"}, role="network")
    sweep = sw.Sweep(_repo(), None, "h1", Window(start=datetime(2024, 11, 18, tzinfo=UTC),
                                                 end=datetime(2024, 11, 19, tzinfo=UTC)), {"t": contract})
    sweep._profiles = {"t": profile}
    groups = sweep._any_of_for("t", contract)
    assert [Predicate(field="event.dataset", op="in", value=["suricata.eve"])] in groups


def test_pivot_prefilter_reads_the_parsed_event_type():
    from romulus.hunt.pivot import _prefilter_raw

    alert, tls = shipped(EVE["alert"], AGENT, "a"), shipped(EVE["tls"], AGENT, "t")
    assert [hit["_id"] for hit in _prefilter_raw([alert, tls], {"net_alert"})] == ["a"]
