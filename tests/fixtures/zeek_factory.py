"""Synthetic Zeek records for tests: one logical record written in every shipper layout ROMULUS reads.

Every value here is synthetic (documentation addresses, made-up uids). Only the published field layouts are
reproduced; no upstream file is copied:

- Zeek's own conn.log fields and their meaning: zeek/zeek scripts/base/protocols/conn/main.zeek (BSD-3-Clause).
- Malcolm (cisagov/Malcolm, Apache-2.0): logstash/pipelines/zeek/1001_zeek_parse.conf (JSON lines parsed with literal
  dotted keys, the `id.*` fields renamed), 1015_zeek_conn.conf at commit 207c4a9e7e68fa13f758b350994d08b202a129f4
  (service lowercased and split, byte and packet copies to ECS fields, `ipProtocol`, conn_long rows rewritten as conn
  with `zeek.conn.long` "true"), 1200_zeek_mutate.conf (columns under `zeek.<log>`, shared fields lifted, `zeek.ts`
  rewritten, `firstPacket`/`lastPacket`/`length` in milliseconds, `event.duration` in nanoseconds, `event.provider`
  "zeek", `event.dataset` the bare log name, `rootId`), enrichment/97_arkimize.conf (`node`).
- Elastic (elastic/integrations packages/zeek 5.0.1, Elastic License 2.0): data_stream/connection/sample_event.json
  for the document layout and elasticsearch/ingest_pipeline/default.yml at commit
  611fffe2ace9ff3ba385ef77233079df6e7b47eb for the renames (`orig_bytes`, `resp_bytes` and `tunnel_parents` removed,
  ICMP ports moved to `zeek.connection.icmp.type`/`.code`, `event.duration` in nanoseconds, `event.original` kept);
  elastic/beats x-pack/filebeat/module/zeek/connection/config/connection.yml for the Filebeat module (the same
  renames, plus Filebeat's `event.module` "zeek").
- Security Onion 2.4 (Security-Onion-Solutions/securityonion branch 2.4/main):
  salt/elasticfleet/files/integrations-dynamic/grid-nodes_general/zeek-logs.json (`event.module` "zeek",
  `data_stream.dataset` "zeek"), salt/elasticsearch/files/ingest/zeek.conn at commit
  c29f11863e96b86540fae76386c5e5ec3b8fe7d4 (`event.dataset` "conn" and its renames, `event.duration` in seconds),
  salt/elasticsearch/files/ingest/zeek.common (`log.id.uid`, `source.*`, `observer.name` from `agent.name`) and
  salt/elasticsearch/files/ingest-dynamic/common at commit 742649a33797ceb85a111402fb48cd3839d2fcbb (the dataset
  prefixed with the module: "zeek.conn").

The analyzer logs' records and writers are in tests/fixtures/zeek_logs.py.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta

from romulus.evidence.community import community_id
from tests.fixtures import zeek_logs

SENSOR = "sensor-zeek-01"
# Malcolm, Elastic and Security Onion keep Zeek's first-packet time to the millisecond, so the logical records here
# are given millisecond times; plain Zeek JSON keeps whatever Zeek wrote.
T0 = 1731938400.123                         # 2024-11-18T14:00:00.123Z
UID = "CHhAvVGS1DHFjwGM9"
PARENT_UID = "CXWfTK3LRdiuQxBbM6"
INDEX = {"malcolm": "arkime_sessions3-241118", "elastic": "logs-zeek.connection-default",
         "security_onion": "logs-zeek-so", "plain": "zeek-json-241118"}
SHAPES = ("malcolm", "elastic", "security_onion", "plain")


@dataclass(frozen=True)
class Conn:
    """One logical Zeek conn.log record, in Zeek's own field names. None means Zeek did not write the field."""
    uid: str = UID
    ts: float = T0
    orig_h: str = "10.0.0.5"
    orig_p: int = 51000
    resp_h: str = "203.0.113.10"
    resp_p: int = 443
    proto: str = "tcp"
    service: str | None = "ssl"                       # Zeek writes a comma-separated string
    duration: float | None = 2.5
    orig_bytes: int | None = 1200
    resp_bytes: int | None = 18000
    conn_state: str | None = "SF"
    local_orig: bool | None = True
    local_resp: bool | None = False
    missed_bytes: int | None = 0
    history: str | None = "ShADadFf"
    orig_pkts: int | None = 14
    orig_ip_bytes: int | None = 1932
    resp_pkts: int | None = 16
    resp_ip_bytes: int | None = 18832
    tunnel_parents: tuple[str, ...] = ()
    ip_proto: int | None = 6
    vlan: int | None = None
    inner_vlan: int | None = None
    orig_l2_addr: str | None = "00:00:5e:00:53:01"
    resp_l2_addr: str | None = "00:00:5e:00:53:af"
    ja4t: str | None = None
    ja4ts: str | None = None
    ja4l: str | None = None
    ja4ls: str | None = None
    community: str | None = field(default="compute")   # "compute": the shipper wrote the seed-0 Community ID

    @property
    def community_id(self) -> str | None:
        if self.community == "compute":
            return community_id(self.orig_h, self.orig_p, self.resp_h, self.resp_p, self.proto)
        return self.community

    def services(self) -> list[str]:
        return [s for s in (self.service or "").split(",") if s]


def iso_ms(ts: float) -> str:
    ms = round(ts * 1000)
    when = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=ms // 1000)
    return when.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms % 1000:03d}Z"


def zeek_json(conn: Conn) -> dict:
    """The record as Zeek's JSON writer emits it: literal dotted `id.*` keys, unset fields omitted, sets as arrays."""
    out = {"ts": conn.ts, "uid": conn.uid, "id.orig_h": conn.orig_h, "id.orig_p": conn.orig_p,
           "id.resp_h": conn.resp_h, "id.resp_p": conn.resp_p, "proto": conn.proto}
    for name in ("service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
                 "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "ip_proto",
                 "vlan", "inner_vlan", "orig_l2_addr", "resp_l2_addr", "ja4t", "ja4ts", "ja4l", "ja4ls"):
        value = getattr(conn, name)
        if value is not None:
            out[name] = value
    if conn.tunnel_parents:
        out["tunnel_parents"] = list(conn.tunnel_parents)
    if conn.community_id is not None:
        out["community_id"] = conn.community_id
    return out


def _text(value):
    """Zeek's text-log form of a value, as Malcolm keeps it for logs it reads as text."""
    if isinstance(value, bool):
        return "T" if value else "F"
    return value if value is None else str(value)


def _prune(obj):
    if isinstance(obj, dict):
        pruned = {k: _prune(v) for k, v in obj.items()}
        return {k: v for k, v in pruned.items() if v is not None and v != {}}
    return obj


def hit(shape: str, source: dict, nid: str) -> dict:
    return {"_index": INDEX[shape], "_id": nid, "_source": source}


# ---- the four layouts ------------------------------------------------------------------------------------------

def malcolm(conn: Conn, nid: str = "mc-1", *, sensor: str | None = SENSOR, text: bool = False,
            interim: bool = False) -> dict:
    """Malcolm's Logstash output for one conn row. `text`: a row Malcolm read from a text (TSV) log, whose values
    stay Zeek's text; `interim`: a conn_long row."""
    t = _text if text else (lambda v: v)
    ms = round(conn.ts * 1000)
    length = round(conn.duration * 1000) if conn.duration is not None else 0
    services = conn.services()
    zeek_conn = {"duration": t(conn.duration), "orig_bytes": t(conn.orig_bytes), "resp_bytes": t(conn.resp_bytes),
                 "conn_state": conn.conn_state, "local_orig": t(conn.local_orig), "local_resp": t(conn.local_resp),
                 "missed_bytes": t(conn.missed_bytes), "history": conn.history, "orig_pkts": t(conn.orig_pkts),
                 "orig_ip_bytes": t(conn.orig_ip_bytes), "resp_pkts": t(conn.resp_pkts),
                 "resp_ip_bytes": t(conn.resp_ip_bytes), "vlan": t(conn.vlan),
                 "inner_vlan": t(conn.inner_vlan), "ja4t": conn.ja4t, "ja4ts": conn.ja4ts, "ja4l": conn.ja4l,
                 "ja4ls": conn.ja4ls,
                 "tunnel_parents": list(conn.tunnel_parents) or None,
                 "long": "true" if interim else None}
    source = {
        "@timestamp": iso_ms(conn.ts), "timestamp": ms, "firstPacket": ms, "lastPacket": ms + length,
        "length": length,
        "event": {"provider": "zeek", "dataset": "conn",
                  "duration": round(conn.duration * 1e9) if conn.duration is not None else None},
        "node": sensor, "host": {"name": sensor},
        "rootId": conn.tunnel_parents[0] if conn.tunnel_parents and text else conn.uid,
        "zeek": {"uid": conn.uid, "ts": iso_ms(conn.ts), "conn": zeek_conn},
        "source": {"ip": conn.orig_h, "port": t(conn.orig_p), "bytes": t(conn.orig_ip_bytes),
                   "packets": t(conn.orig_pkts), "mac": conn.orig_l2_addr},
        "destination": {"ip": conn.resp_h, "port": t(conn.resp_p), "bytes": t(conn.resp_ip_bytes),
                        "packets": t(conn.resp_pkts), "mac": conn.resp_l2_addr},
        "client": {"bytes": t(conn.orig_bytes)}, "server": {"bytes": t(conn.resp_bytes)},
        "network": {"transport": conn.proto, "protocol": services or None, "community_id": conn.community_id},
        "protocol": services or None, "ipProtocol": t(conn.ip_proto),
    }
    return hit("malcolm", _prune(source), nid)


def elastic(conn: Conn, nid: str = "el-1", *, sensor: str | None = SENSOR, original: bool = True,
            filebeat: bool = False) -> dict:
    """The Elastic Agent integration's document for one conn row (`filebeat`: the Filebeat zeek module's, which writes
    `event.module`, `fileset.name` and no data stream: elastic/beats x-pack/filebeat/module/zeek/connection/test/
    connection-json.log-expected.json at commit bd26a932c991bdd42314ab5f7fdf7ad7539e2584). `original`: the Zeek line
    kept in event.original."""
    zeek_connection = {"state": conn.conn_state, "history": conn.history, "local_orig": conn.local_orig,
                       "local_resp": conn.local_resp, "missed_bytes": conn.missed_bytes, "vlan": conn.vlan,
                       "inner_vlan": conn.inner_vlan, "ja4t": conn.ja4t, "ja4ts": conn.ja4ts, "ja4l": conn.ja4l,
                       "ja4ls": conn.ja4ls, "ip_proto": conn.ip_proto}
    source_side = {"address": conn.orig_h, "ip": conn.orig_h, "port": conn.orig_p, "bytes": conn.orig_ip_bytes,
                   "packets": conn.orig_pkts, "mac": conn.orig_l2_addr}
    destination_side = {"address": conn.resp_h, "ip": conn.resp_h, "port": conn.resp_p,
                        "bytes": conn.resp_ip_bytes, "packets": conn.resp_pkts, "mac": conn.resp_l2_addr}
    if conn.proto == "icmp":
        zeek_connection["icmp"] = {"type": source_side.pop("port"), "code": destination_side.pop("port")}
    event = {"dataset": "zeek.connection", "kind": "event", "category": ["network"], "id": conn.uid,
             "duration": round(conn.duration * 1e9) if conn.duration is not None else None,
             "original": json.dumps(zeek_json(conn)) if original else None,
             "module": "zeek" if filebeat else None}
    source = {"@timestamp": iso_ms(conn.ts), "agent": {"name": sensor, "type": "filebeat"},
              "host": {"name": f"{sensor}-shipper" if sensor else None},
              "data_stream": None if filebeat else {"dataset": "zeek.connection", "type": "logs"}, "event": event,
              "fileset": {"name": "connection"} if filebeat else None,
              "service": {"type": "zeek"} if filebeat else None,
              "source": source_side, "destination": destination_side,
              "network": {"transport": conn.proto, "protocol": conn.service, "community_id": conn.community_id},
              "zeek": {"session_id": conn.uid, "connection": zeek_connection},
              "tags": ["preserve_original_event", "zeek-connection"] if original else ["zeek-connection"]}
    return hit("elastic", _prune(source), nid)


def security_onion(conn: Conn, nid: str = "so-1", *, sensor: str | None = SENSOR, bare: bool = False) -> dict:
    """Security Onion 2.4's document for one conn row: its common pipeline prefixes the dataset with the module
    ("zeek.conn"); `bare`: a record that did not pass that pipeline ("conn"). Its `message` keeps the Zeek line: a
    normalizer never parses it."""
    source = {
        "@timestamp": iso_ms(conn.ts), "message": json.dumps(zeek_json(conn)),
        "event": {"module": "zeek", "dataset": "conn" if bare else "zeek.conn", "category": "network",
                  "duration": conn.duration},
        "data_stream": {"dataset": "zeek", "namespace": "so"}, "observer": {"name": sensor}, "tags": ["conn"],
        "source": {"ip": conn.orig_h, "port": conn.orig_p}, "destination": {"ip": conn.resp_h, "port": conn.resp_p},
        "client": {"ip": conn.orig_h, "port": conn.orig_p, "bytes": conn.orig_bytes, "packets": conn.orig_pkts,
                   "ip_bytes": conn.orig_ip_bytes},
        "server": {"ip": conn.resp_h, "port": conn.resp_p, "bytes": conn.resp_bytes, "packets": conn.resp_pkts,
                   "ip_bytes": conn.resp_ip_bytes},
        "network": {"transport": conn.proto, "protocol": conn.service, "community_id": conn.community_id,
                    "vlan": {"id": conn.vlan}},
        "connection": {"state": conn.conn_state, "history": conn.history, "bytes": {"missed": conn.missed_bytes},
                       "local": {"originator": conn.local_orig, "responder": conn.local_resp}},
        "log": {"id": {"uid": conn.uid, "tunnel_parents": list(conn.tunnel_parents) or None}},
        "hash": {"ja4t": conn.ja4t, "ja4ts": conn.ja4ts, "ja4l": conn.ja4l, "ja4ls": conn.ja4ls},
    }
    return hit("security_onion", _prune(source), nid)


def plain(conn: Conn, nid: str = "pl-1", *, path: str | None = "conn", expanded: bool = False) -> dict:
    """Zeek's JSON line indexed as it is: literal dotted keys, and `_path` when the json-streaming-logs package
    wrote it. `expanded`: a shipper that expanded the dotted keys into objects."""
    source = zeek_json(conn)
    if expanded:
        ids = {key.split(".", 1)[1]: source.pop(key) for key in [k for k in source if k.startswith("id.")]}
        source["id"] = ids
    if path is not None:
        source = {"_path": path, **source}
    return hit("plain", source, nid)


WRITERS = {"malcolm": malcolm, "elastic": elastic, "security_onion": security_onion, "plain": plain}


def in_every_shape(record: Conn | zeek_logs.Row, prefix: str = "") -> dict[str, dict]:
    """The logical record in every shape that writes its log (a conn record, or an analyzer log's row)."""
    if isinstance(record, zeek_logs.Row):
        return zeek_logs.in_every_shape(record, prefix)
    return {shape: WRITERS[shape](record, f"{prefix}{shape}") for shape in SHAPES}


# ---- the logical records the tests need ---------------------------------------------------------------------------

# Zeek's conn_state codes with a history of the shape each describes (uppercase: originator, lowercase: responder).
CONN_STATES = {
    "S0": ("S", None, None),                    # a SYN, no reply
    "S1": ("ShA", 0, 0),                        # established, not terminated
    "SF": ("ShADadFf", 1200, 18000),            # normal establishment and termination
    "REJ": ("Sr", 0, 0),                        # rejected
    "S2": ("ShADadF", 400, 900),                # established, the originator closed
    "S3": ("ShADadf", 400, 900),                # established, the responder closed
    "RSTO": ("ShADadR", 400, 900),              # the originator aborted
    "RSTR": ("ShADadr", 400, 900),              # the responder aborted
    "RSTOS0": ("SR", 0, 0),                     # the originator sent a SYN then a RST
    "RSTRH": ("Hr", 0, 0),                      # the responder sent a SYN-ACK then a RST
    "SH": ("SF", 0, 0),                         # the originator sent a SYN then a FIN
    "SHR": ("Hf", 0, 0),                        # the responder sent a SYN-ACK then a FIN
    "OTH": ("DdA", 300, 300),                   # mid-stream traffic, no SYN seen
}


def conn_in_state(state: str, **changes) -> Conn:
    history, orig_bytes, resp_bytes = CONN_STATES[state]
    return replace(Conn(conn_state=state, history=history, orig_bytes=orig_bytes, resp_bytes=resp_bytes), **changes)


HISTORY_CLASSES = {
    "opened_by_orig": "ShADadFf",
    "flipped": "^hADadfF",                      # Zeek's heuristic flipped the direction
    "midstream": "DdAa",
    "content_gap": "ShADgdFf",                  # g: a content gap
    "partial": "ShADadxFf",                     # x: analysis partial (limits exceeded)
}

ICMP_ECHO = Conn(proto="icmp", orig_p=8, resp_p=0, service=None, history=None, conn_state="OTH", orig_bytes=5600,
                 resp_bytes=5600, orig_pkts=100, resp_pkts=100, orig_ip_bytes=8400, resp_ip_bytes=8400, ip_proto=1,
                 community="1:synthetic-icmp=", local_orig=None, local_resp=None)
ICMP6_ECHO = replace(ICMP_ECHO, orig_h="fd00::5", resp_h="2001:db8::50", orig_p=128, resp_p=129, ip_proto=58,
                     community="1:synthetic-icmp6=")
ICMP_UNREACHABLE = replace(ICMP_ECHO, orig_p=3, resp_p=1, orig_bytes=56, resp_bytes=0, orig_pkts=1, resp_pkts=0,
                           orig_ip_bytes=84, resp_ip_bytes=0)
IPV6_TCP = Conn(orig_h="2001:db8::5", resp_h="2001:db8:1::10", resp_p=22, service="ssh")
UDP_DNS = Conn(proto="udp", orig_p=53000, resp_h="198.51.100.53", resp_p=53, service="dns", history="Dd",
               duration=0.012, orig_bytes=40, resp_bytes=120, orig_pkts=1, resp_pkts=1, orig_ip_bytes=68,
               resp_ip_bytes=148, ip_proto=17)
TUNNELLED = Conn(uid="CinnerTunnel001", tunnel_parents=(PARENT_UID,), resp_p=80, service="http")
# every field any shape writes: the gate that each catalogued path is read
FULL = Conn(tunnel_parents=(PARENT_UID,), vlan=110, inner_vlan=220, ja4t="64240_2-4-8-1-3_1460_8",
            ja4ts="65160_2-4-8-1-3_1460_7", ja4l="1050_64", ja4ls="2120_128")
# a logical record per catalogued log (the gate test fails when a catalogued log has none)
LOG_FIXTURES: dict[str, Conn | zeek_logs.Row] = {"conn": FULL, **zeek_logs.ROWS}
MULTI_SERVICE = Conn(resp_p=445, service="gssapi,smb,krb,dce_rpc,ntlm")
REMOVED_SERVICE = Conn(resp_p=8443, service="http,-ssl")
SPICY_SERVICE = Conn(resp_p=88, service="spicy_krb_tcp")


# ---- malformed rows ---------------------------------------------------------------------------------------------

def malformed_rows() -> list[tuple[str, dict, str]]:
    """(name, hit, what normalization must make of it): "error" (the record is unreadable), "skip", or a native path
    that is dropped and listed in parse.malformed while the rest of the record is kept."""
    rows: list[tuple[str, dict, str]] = []

    def mutated(name, shape, mutate, outcome, conn=None):
        h = WRITERS[shape](conn or Conn(), f"bad-{name}")
        mutate(h["_source"])
        rows.append((name, h, outcome))

    mutated("port-string", "elastic", lambda s: s["source"].update(port="fifty"), "source.port")
    mutated("port-range", "plain", lambda s: s.update({"id.resp_p": 70000}), "id.resp_p")
    mutated("bytes-negative", "plain", lambda s: s.update(orig_bytes=-5), "orig_bytes")
    mutated("bytes-bool", "security_onion", lambda s: s["client"].update(bytes=True), "client.bytes")
    mutated("bytes-array", "malcolm", lambda s: s["zeek"]["conn"].update(orig_bytes=[1, 2]), "zeek.conn.orig_bytes")
    mutated("duration-text", "plain", lambda s: s.update(duration="long"), "duration")
    mutated("history-number", "elastic", lambda s: s["zeek"]["connection"].update(history=7),
            "zeek.connection.history")
    mutated("flag-text", "plain", lambda s: s.update(local_orig="maybe"), "local_orig")
    mutated("ip-garbage", "plain", lambda s: s.update({"id.orig_h": "not-an-address"}), "id.orig_h")
    mutated("ip-array", "malcolm", lambda s: s["source"].update(ip=["10.0.0.5", "10.0.0.6"]), "source.ip")
    mutated("uid-array", "security_onion", lambda s: s["log"]["id"].update(uid=["a", "b"]), "log.id.uid")
    mutated("service-number", "plain", lambda s: s.update(service=5), "service")
    mutated("parents-numbers", "plain", lambda s: s.update(tunnel_parents=[1, 2]), "tunnel_parents",
            TUNNELLED)
    mutated("original-not-json", "elastic", lambda s: s["event"].update(original="ts\tuid\t..."), "event.original")
    # a value standing where an object belongs, a sensor that is not one name, a path written twice
    mutated("conn-object-string", "malcolm", lambda s: s["zeek"].update(conn="not an object"), "zeek.conn")
    mutated("zeek-not-object", "malcolm", lambda s: s.update(zeek="x"), "zeek")
    mutated("source-not-object", "malcolm", lambda s: s.update(source="x"), "source")
    mutated("node-list", "malcolm", lambda s: s.update(node=["a", "b"]), "node")
    mutated("agent-name-number", "elastic", lambda s: s["agent"].update(name=7), "agent.name")
    mutated("nested-and-literal-disagree", "malcolm", lambda s: s["zeek"].update({"conn.history": "Dd"}),
            "zeek.conn.history")
    mutated("plain-nested-and-literal-disagree", "plain", lambda s: s.update(id={"orig_h": "10.9.9.9"}),
            "id.orig_h")
    # placeholders Zeek writes for unset and empty values are absent, never malformed
    mutated("placeholders", "malcolm",
            lambda s: s["zeek"]["conn"].update(history="-", tunnel_parents="(empty)", orig_bytes="-"),
            "absent", Conn())
    # unreadable: no time, no log name, a log name of the wrong type
    mutated("no-time", "plain", lambda s: s.pop("ts"), "error")
    mutated("time-garbage", "elastic", lambda s: s.update({"@timestamp": "yesterday"}), "error")
    # no readable log name: not taken as Zeek, the record keeps the path it took before (here an Arkime session)
    mutated("no-log-name", "malcolm", lambda s: s["event"].pop("dataset"), "not-zeek")
    mutated("log-name-number", "security_onion", lambda s: s["event"].update(dataset=5), "error")
    mutated("uncatalogued-log", "malcolm", lambda s: s["event"].update(dataset="kerberos"), "skip")
    mutated("dataset-array-uncatalogued", "malcolm", lambda s: s["event"].update(dataset=["smb_files", "smb_cmd"]),
            "skip")
    # a list naming a catalogued log is that log only when the row carries the log's object
    mutated("dataset-array-without-object", "malcolm",
            lambda s: (s["event"].update(dataset=["conn", "dns"]), s["zeek"].pop("conn")), "skip")
    return rows


# Out-of-range times and durations, as each shape writes them: (seconds, how the shape writes them).
HUGE_DURATIONS = (1e12, 1e13, 1e15, 10**400)
LAST_SECOND = 253402300799.0                    # 9999-12-31T23:59:59Z: any duration takes the end out of range


def overflow_rows() -> list[tuple[str, dict]]:
    """Rows whose end time or duration no time value can hold, in every shape. Each must type the record with
    flow.end left out and the offending path listed in parse.malformed; none may raise."""
    rows: list[tuple[str, dict]] = []
    for seconds in HUGE_DURATIONS:
        label = f"{seconds:.0e}" if isinstance(seconds, float) else "1e400"
        h = malcolm(Conn(), f"mc-{label}")
        h["_source"]["zeek"]["conn"]["duration"] = seconds
        rows.append((f"malcolm-duration-{label}", h))
        h = elastic(Conn(), f"el-{label}")
        h["_source"]["event"]["duration"] = int(seconds) * 10**9
        rows.append((f"elastic-duration-{label}", h))
        h = security_onion(Conn(), f"so-{label}")
        h["_source"]["event"]["duration"] = seconds
        rows.append((f"security-onion-duration-{label}", h))
        h = plain(Conn(), f"pl-{label}")
        h["_source"]["duration"] = seconds
        rows.append((f"plain-duration-{label}", h))
    text = malcolm(Conn(), "mc-text-huge", text=True)
    text["_source"]["zeek"]["conn"]["duration"] = "9" * 400
    rows.append(("malcolm-text-duration-400-digits", text))
    last = replace(Conn(), ts=LAST_SECOND)
    for shape in SHAPES:
        rows.append((f"{shape}-start-9999-12-31", WRITERS[shape](last, f"{shape}-9999")))
    return rows


# ---- previously normalized shapes: what Zeek dispatch must leave unchanged -----------------------------------------

def _eve(nid: str, record: dict) -> dict:
    record = {"timestamp": "2024-11-18T14:26:40.100000+0000", "flow_id": 1234, "src_ip": "172.17.100.121",
              "src_port": 51000, "dest_ip": "192.0.2.174", "dest_port": 443, "proto": "TCP",
              "community_id": "1:abc=", **record}
    return {"_id": nid, "_index": "romulus-network-logs", "_source": {
        "@timestamp": "2024-11-18T14:26:40.100Z", "host": {"name": "inetfw"},
        "event": {"dataset": f"suricata.eve.{record['event_type']}", "original": json.dumps(record)}}}


def _malcolm_suricata(nid: str, dataset: str, suricata: dict, **top) -> dict:
    src = {"@timestamp": "2024-11-18T14:00:05.000Z", "event": {"provider": "suricata", "dataset": dataset},
           "host": {"name": "sensor-01"}, "node": "sensor-01", "firstPacket": 1731938400000,
           "lastPacket": 1731938405000, "source": {"ip": "10.0.0.5", "port": 51000},
           "destination": {"ip": "203.0.113.10", "port": 443}, "suricata": {
               "timestamp": "2024-11-18T14:00:05.000Z", "flow_id": 99, **suricata}, **top}
    return {"_id": nid, "_index": "arkime_sessions3-241118", "_source": src}


def _arkime(nid: str, **extra) -> dict:
    ms = 1731940000000
    src = {"firstPacket": ms, "lastPacket": ms + 2000, "ipProtocol": 6, "node": "capture-01",
           "network": {"community_id": "1:abc="},
           "source": {"ip": "172.17.100.121", "port": 51000, "bytes": 900, "packets": 9},
           "destination": {"ip": "192.0.2.174", "port": 443, "bytes": 4000, "packets": 8},
           "client": {"bytes": 300}, "server": {"bytes": 2900}, "protocol": ["tcp", "tls"],
           "tcpflags": {"syn": 1, "syn-ack": 1, "ack": 10}, **extra}
    return {"_id": nid, "_index": "arkime_sessions3-241118", "_source": src}


def legacy_zeek_icmp(nid: str = "z1", *, source_port=8, destination_port=0, connection=None,
                     transport="icmp", source_ip="172.17.100.121", destination_ip="192.0.2.174") -> dict:
    """The Zeek ICMP record shape the ICMP-only normalizer was written against: an Elastic-style document keeping
    Zeek's own counter names under zeek.connection."""
    source = {"@timestamp": "2024-11-18T14:26:40.100Z", "host": {"name": "zeek1"},
              "event": {"dataset": "zeek.connection"}, "network": {"transport": transport},
              "source": {"ip": source_ip, "port": source_port},
              "destination": {"ip": destination_ip, "port": destination_port},
              "zeek": {"connection": connection or {"orig_bytes": 900, "resp_bytes": 4000,
                                                    "orig_pkts": 9, "resp_pkts": 8, "duration": 2.0}}}
    return {"_id": nid, "_index": "romulus-network-logs", "_source": source}


_HTTP = {"hostname": "www.example.test", "url": "/index.html", "http_user_agent": "ExampleAgent/1.0",
         "http_content_type": "text/html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 1024}
_SSH = {"client": {"proto_version": "2.0", "software_version": "paramiko_3.4.0", "hassh": {"hash": "abc"}},
        "server": {"proto_version": "2.0", "software_version": "OpenSSH_9.6"}}
_DNS = {"version": 2, "type": "answer", "id": 7, "rrname": "a.example", "rrtype": "A", "rcode": "NOERROR",
        "answers": [{"rrname": "a.example", "rrtype": "A", "ttl": 30, "rdata": "192.0.2.9"}]}
# Zeek logs outside the catalog, as each shipper names them: their rows keep the skip every unread dataset gets.
UNCATALOGUED_LOGS = ("dns", "http", "ssl", "x509", "files", "ssh", "notice", "weird", "smb_files")


def _uncatalogued(shape: str, log: str) -> dict:
    h = WRITERS[shape](Conn(), f"zeek-uncatalogued-{shape}-{log}")
    if shape == "elastic":
        h["_source"]["event"]["dataset"] = h["_source"]["data_stream"]["dataset"] = f"zeek.{log}"
    elif shape == "plain":
        h["_source"]["_path"] = log
    else:
        h["_source"]["event"]["dataset"] = log
    return h


def _host_records() -> dict[str, list[dict]]:
    """An audit event's records, a journal record and Apache records from the throughput fixture, and Windows events
    in two shipper shapes."""
    from tests import throughput_fixture, windows_fixtures
    host = throughput_fixture.build(1)[throughput_fixture.HOST_TARGET]
    first = next(h for h in host if h["_source"]["event"]["dataset"] == "linux.audit")
    serial = first["_source"]["event"]["original"].split("msg=", 1)[1].split(")", 1)[0]
    out = {"linux-audit-group": [h for h in host if h["_source"]["event"]["dataset"] == "linux.audit"
                                 and f"msg={serial})" in h["_source"]["event"]["original"]]}
    for dataset in ("systemd.journal", "apache.access", "apache.error"):
        out[dataset.replace(".", "-")] = [next(h for h in host if h["_source"]["event"]["dataset"] == dataset)]
    out["systemd-journal-sshd"] = [next(h for h in host if h["_source"]["event"]["dataset"] == "systemd.journal"
                                        and '"SYSLOG_IDENTIFIER": "sshd"' in h["_source"]["event"].get("original", ""))]
    events = windows_fixtures.all_logical_events()
    sysmon = next(e for e in events if e.provider == "Microsoft-Windows-Sysmon")
    for event, label in ((events[0], "security"), (sysmon, "sysmon")):
        for shape in ("winlogbeat_8", "elastic_agent"):
            out[f"windows-{label}-{shape}"] = [windows_fixtures.windows_hit(event, shape)]
    return out


def previous_shapes() -> dict[str, list[dict]]:
    """Records of every shape that normalized, or was counted as skipped, before Zeek dispatch existed, in the groups
    normalize_hits reads together (an audit event's records). The Zeek rows of logs outside the catalog are among
    them: until their log is normalized they keep the skip they had."""
    single = {
        "eve-http": _eve("eve-http", {"event_type": "http", "dest_port": 80, "http": _HTTP}),
        "eve-fileinfo": _eve("eve-fileinfo", {"event_type": "fileinfo", "dest_port": 80, "http": _HTTP, "fileinfo": {
            "filename": "/files/report.pdf", "size": 2048, "state": "CLOSED", "gaps": False}}),
        "eve-ssh": _eve("eve-ssh", {"event_type": "ssh", "dest_port": 22, "ssh": _SSH}),
        "malcolm-suricata-dns": _malcolm_suricata(
            "malcolm-suricata-dns", "dns", {"dns": _DNS}, source={"ip": "10.0.0.5", "port": 53000},
            destination={"ip": "198.51.100.53", "port": 53}, network={"transport": "udp", "protocol": ["dns"]}),
        "malcolm-suricata-http": _malcolm_suricata(
            "malcolm-suricata-http", "http", {"tx_id": 0, "http": _HTTP},
            destination={"ip": "203.0.113.10", "port": 80}, network={"transport": "tcp", "protocol": ["http"]}),
        "malcolm-suricata-fileinfo": _malcolm_suricata(
            "malcolm-suricata-fileinfo", "fileinfo",
            {"http": _HTTP, "fileinfo": {"filename": "/files/report.pdf", "size": 2048, "state": "CLOSED"}},
            destination={"ip": "203.0.113.10", "port": 80}, network={"transport": "tcp", "protocol": ["http"]}),
        "malcolm-suricata-tls": _malcolm_suricata(
            "malcolm-suricata-tls", "tls",
            {"tls": {"subject": "CN=www.example.test", "issuerdn": "CN=Example CA", "sni": "www.example.test",
                     "notbefore": "2024-01-01T00:00:00.000Z", "notafter": "2025-01-01T00:00:00.000Z"}},
            network={"transport": "tcp", "protocol": ["tls"]},
            tls={"version": "TLS 1.2", "client": {"ja3": "e7d705a3286e19ea42f587b344ee6865"}}),
        "malcolm-suricata-ssh": _malcolm_suricata(
            "malcolm-suricata-ssh", "ssh", {"ssh": _SSH}, destination={"ip": "203.0.113.10", "port": 22},
            network={"transport": "tcp", "protocol": ["ssh"]}),
        "malcolm-suricata-netflow": _malcolm_suricata(
            "malcolm-suricata-netflow", "netflow", {"netflow": {"pkts": 1, "bytes": 74,
                                                                 "start": "2024-11-18T14:00:00.000Z",
                                                                 "end": "2024-11-18T14:00:00.000Z"}},
            source={"ip": "10.0.0.5", "port": 53000}, destination={"ip": "198.51.100.53", "port": 53},
            network={"transport": "udp", "protocol": ["dns"]}),
        "malcolm-suricata-ftp": _malcolm_suricata(
            "malcolm-suricata-ftp", "flow", {"flow": {"bytes_toserver": 400, "bytes_toclient": 900,
                                                      "pkts_toserver": 4, "pkts_toclient": 5, "state": "closed",
                                                      "start": "2024-11-18T14:00:00.000Z",
                                                      "end": "2024-11-18T14:00:04.000Z"}},
            destination={"ip": "203.0.113.10", "port": 21}, network={"transport": "tcp", "protocol": ["ftp"]}),
        # a dotted dataset that is not zeek.* is no Zeek log name, whatever the module says
        "zeek-module-with-suricata-dataset": {"_id": "zeek-module-with-suricata-dataset", "_index": "logs-x",
                                              "_source": {
            "@timestamp": "2024-11-18T14:26:40.100Z", "event": {
                "module": "zeek", "dataset": "suricata.eve.alert", "original": json.dumps({
                    "timestamp": "2024-11-18T14:26:40.100000+0000", "event_type": "alert", "src_ip": "10.0.0.5",
                    "src_port": 51000, "dest_ip": "203.0.113.10", "dest_port": 80, "proto": "TCP",
                    "alert": {"signature": "ET INFO Example", "signature_id": 1, "severity": 3}})}}},
        **{f"zeek-uncatalogued-{shape}-{log}": _uncatalogued(shape, log)
           for shape in ("malcolm", "elastic", "security_onion") for log in UNCATALOGUED_LOGS},
        **_previous_network(),
    }
    return {**{name: [h] for name, h in single.items()}, **_host_records()}


def dispatch_records() -> dict[str, list[dict]]:
    """Every record group the dispatch golden holds: the previous shapes, and Zeek rows of every catalogued log in every
    shape that writes it (named zeek-<log>-<shape>), Zeek 5.0's files layout, and the conn record of a Security Onion
    sensor whose records did not pass its common pipeline. Each group's rows name a sensor of their own, so no copy
    merges across groups in the one-batch reading."""
    out = dict(previous_shapes())
    for name, record in LOG_FIXTURES.items():
        for shape in zeek_logs.shapes_of(name) if name != "conn" else SHAPES:
            nid, sensor = f"golden-{shape}-{name}", f"sensor-{shape}-{name}"
            if name == "conn":
                h = WRITERS[shape](record, nid) if shape == "plain" else WRITERS[shape](record, nid, sensor=sensor)
            else:
                h = zeek_logs.WRITERS[shape](record, nid) if shape == "plain" else \
                    zeek_logs.WRITERS[shape](record, nid, sensor=sensor)
            out[f"zeek-{name}-{shape}"] = [h]
    for shape in SHAPES:
        nid, sensor = f"golden-{shape}-files-5.0", f"sensor-{shape}-files-5.0"
        writer = zeek_logs.WRITERS[shape]
        out[f"zeek-files-5.0-{shape}"] = [writer(zeek_logs.FILES_50, nid) if shape == "plain"
                                          else writer(zeek_logs.FILES_50, nid, sensor=sensor)]
    out["zeek-conn-security_onion-bare"] = [security_onion(FULL, "golden-security_onion-bare",
                                                           sensor="sensor-security_onion-bare", bare=True)]
    return out


def _previous_network() -> dict[str, dict]:
    return {
        "eve-flow": _eve("eve-flow", {"event_type": "flow", "app_proto": "tls", "flow": {
            "bytes_toserver": 1200, "bytes_toclient": 9000, "pkts_toserver": 10, "pkts_toclient": 9,
            "start": "2024-11-18T14:26:30.000000+0000", "end": "2024-11-18T14:26:40.000000+0000", "state": "closed"},
            "tcp": {"syn": True, "tcp_flags_ts": "1b", "tcp_flags_tc": "1b", "state": "closed"}}),
        "eve-alert": _eve("eve-alert", {"event_type": "alert", "alert": {
            "signature": "ET INFO Example", "signature_id": 2000001, "category": "Misc activity", "severity": 2,
            "metadata": {"mitre_technique_id": ["T1071.001"]}}, "app_proto": "http"}),
        "eve-dns": _eve("eve-dns", {"event_type": "dns", "proto": "UDP", "dest_port": 53, "dns": {
            "version": 2, "type": "answer", "id": 7, "rrname": "a.example", "rrtype": "A", "rcode": "NOERROR",
            "answers": [{"rrname": "a.example", "rrtype": "A", "ttl": 30, "rdata": "192.0.2.9"}]}}),
        "eve-tls": _eve("eve-tls", {"event_type": "tls", "tls": {"sni": "c2.example", "version": "TLS 1.2",
                                                               "subject": "CN=c2.example", "issuerdn": "CN=c2.example",
                                                               "ja3": {"hash": "abc"}}}),
        "eve-netflow": _eve("eve-netflow", {"event_type": "netflow", "netflow": {"bytes": 74, "pkts": 1}}),
        "eve-icmp": _eve("eve-icmp", {"event_type": "flow", "proto": "ICMP", "icmp_type": 8, "icmp_code": 0,
                                      "flow": {"bytes_toserver": 900, "bytes_toclient": 900, "pkts_toserver": 9,
                                               "pkts_toclient": 9}}),
        "eve-stats": _eve("eve-stats", {"event_type": "stats", "stats": {"uptime": 3}}),
        "malcolm-suricata-flow": _malcolm_suricata(
            "malcolm-suricata-flow", "flow",
            {"flow": {"bytes_toserver": 2400, "bytes_toclient": 18000, "pkts_toserver": 12, "pkts_toclient": 10,
                      "start": "2024-11-18T14:00:00.000Z", "end": "2024-11-18T14:00:04.250Z", "state": "closed"},
             "tcp": {"syn": True, "tcp_flags_ts": "1b", "tcp_flags_tc": "1b"}},
            network={"transport": "tcp", "protocol": ["tls"], "community_id": "1:abc="}, rootId=99),
        "malcolm-suricata-alert": _malcolm_suricata(
            "malcolm-suricata-alert", "alert",
            {"alert": {"action": "allowed", "severity": 2, "metadata": {"signature_severity": ["Major"]}}},
            network={"transport": "tcp", "protocol": ["http"]}, rule={"name": "ET INFO Example", "id": 2000001,
                                                                      "category": ["Misc activity"]}),
        "arkime": _arkime("arkime"),
        "arkime-provider": _arkime("arkime-provider", event={"provider": "arkime"}),
        "arkime-continuation": _arkime("arkime-continuation", event={"provider": "arkime"}, rootId="arkime"),
        "zeek-icmp": legacy_zeek_icmp("zeek-icmp"),
        "zeek-icmp-reply-first": legacy_zeek_icmp("zeek-icmp-reply-first", source_port=0, destination_port=8),
        "zeek-icmp6": legacy_zeek_icmp("zeek-icmp6", source_port=128, destination_port=129, source_ip="fd00::5",
                                       destination_ip="2001:db8::50"),
        "zeek-icmp-absent-type": legacy_zeek_icmp("zeek-icmp-absent-type", source_port=None,
                                                  destination_port=None),
        "zeek-icmp-explicit": legacy_zeek_icmp("zeek-icmp-explicit", connection={
            "orig_bytes": 10, "resp_bytes": 10, "orig_pkts": 1, "resp_pkts": 1, "icmp_type": 3, "icmp_code": 1}),
        "zeek-icmp-bad-counter": legacy_zeek_icmp("zeek-icmp-bad-counter", connection={
            "orig_bytes": -1, "resp_bytes": "x", "duration": "long"}),
        "apache-access": {"_id": "apache-access", "_index": "logs-apache", "_source": {
            "@timestamp": "2024-11-18T14:00:00.000Z", "host": {"name": "web01"},
            "event": {"dataset": "apache.access"}, "source": {"ip": "198.51.100.7"},
            "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
            "url": {"original": "/index.html"}, "user_agent": {"original": "curl/8.0"}}},
        "unknown-dataset": {"_id": "unknown-dataset", "_index": "logs-x", "_source": {
            "@timestamp": "2024-11-18T14:00:00.000Z", "event": {"dataset": "vendor.thing"}}},
    }


# ---- a mixed Malcolm batch: one index holding Zeek, Arkime and Suricata rows ----------------------------------------

def malcolm_mixed_batch() -> list[dict]:
    """A page of a Malcolm index: Zeek conn rows (TCP, ICMP, an interim row and its final row), Arkime sessions
    with and without a provider (their rootId is their own session id), and a Malcolm Suricata row."""
    final = Conn(uid="ClongLived000001", duration=7200.0, resp_p=8443, service=None, history="ShADadFf")
    return [
        malcolm(Conn(), "mx-zeek-tcp"),
        malcolm(ICMP_ECHO, "mx-zeek-icmp"),
        malcolm(replace(final, duration=600.0, orig_bytes=100, resp_bytes=200), "mx-zeek-interim", interim=True),
        malcolm(final, "mx-zeek-final"),
        _arkime("mx-arkime", rootId="mx-arkime"),
        _arkime("mx-arkime-provider", event={"provider": "arkime"}),
        _previous_network()["malcolm-suricata-flow"],
    ]


# ---- mission-scale volume ------------------------------------------------------------------------------------------

def _volume_conn(i: int, start: float, hosts: int | None = None) -> Conn:
    kind = i % 100
    host = i if hosts is None else i % hosts
    conn = replace(Conn(), uid=f"C{i:017d}", ts=start + i * 0.001,
                   orig_h=f"10.{(host >> 16) & 255}.{(host >> 8) & 255}.{host & 255}", orig_p=32768 + i % 28000,
                   resp_p=443 if kind % 10 else 53)
    if kind == 99:
        return replace(conn, proto="icmp", orig_p=8, resp_p=0, service=None, history=None, ip_proto=1,
                       community=None)
    if kind % 10 == 0:
        return replace(conn, proto="udp", service="dns", history="Dd", ip_proto=17)
    return conn


def stream_conn_hits(n: int, shape: str = "malcolm", *, start: float = T0, hosts: int | None = None,
                     ) -> Iterator[dict]:
    """`n` distinct conn rows written lazily, one at a time: memory does not grow with `n`. Addresses, ports, uids
    and times vary deterministically (`hosts`: the number of distinct source addresses, by default one per row); a
    tenth of the rows are UDP and a hundredth ICMP. Malcolm rows are stamped from one written row per kind (the
    varying fields replaced), so generating them costs little beside normalizing them; other shapes are written in
    full."""
    if shape != "malcolm":
        for i in range(n):
            yield WRITERS[shape](_volume_conn(i, start, hosts), f"{shape}-{i}")
        return
    templates = {kind: malcolm(_volume_conn(kind, start), "template")["_source"] for kind in (1, 10, 99)}
    for i in range(n):
        kind = i % 100
        template = templates[99 if kind == 99 else 10 if kind % 10 == 0 else 1]
        conn = _volume_conn(i, start, hosts)
        ms = round(conn.ts * 1000)
        stamp = iso_ms(conn.ts)
        source = dict(template)
        source.update({"@timestamp": stamp, "timestamp": ms, "firstPacket": ms, "lastPacket": ms + template["length"],
                       "rootId": conn.uid, "zeek": {**template["zeek"], "uid": conn.uid, "ts": stamp},
                       "source": {**template["source"], "ip": conn.orig_h, "port": conn.orig_p},
                       "destination": {**template["destination"], "port": conn.resp_p}})
        if conn.community_id is not None:
            source["network"] = {**template["network"], "community_id": conn.community_id}
        yield hit("malcolm", source, f"malcolm-{i}")


def logical_dict(conn: Conn) -> dict:
    return asdict(conn)
