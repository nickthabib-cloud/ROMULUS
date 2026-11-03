"""The Zeek logs ROMULUS normalizes, with each log's family and, per shipper shape, its name and field locations.

Four shipper shapes are recognized, each by fields the shipper itself writes (never by content or index name):

- ``malcolm``: Malcolm's Logstash pipeline (cisagov/Malcolm, Apache-2.0). ``event.provider`` is "zeek" and
  ``event.dataset`` is the bare log name (an array for some SMB rows); the Zeek columns sit under
  ``zeek.<log>.*`` with the shared ones lifted (logstash/pipelines/zeek/1200_zeek_mutate.conf): ``ts`` to
  ``zeek.ts`` (rewritten as the formatted ``@timestamp``), ``uid`` to ``zeek.uid``, ``id.orig_h``/``id.orig_p``/
  ``id.resp_h``/``id.resp_p`` to ``source.ip``/``source.port``/``destination.ip``/``destination.port``, ``proto`` to
  ``network.transport``, ``service`` to ``network.protocol``, ``orig_l2_addr``/``resp_l2_addr`` to
  ``source.mac``/``destination.mac``, ``community_id`` to ``network.community_id``, ``password`` to
  ``related.password``. For conn (logstash/pipelines/zeek/1015_zeek_conn.conf, commit
  207c4a9e7e68fa13f758b350994d08b202a129f4) the service is lowercased and split into a list, ``ip_proto`` becomes
  ``ipProtocol``, and ``orig_ip_bytes``/``resp_ip_bytes``/``orig_pkts``/``resp_pkts``/``orig_bytes``/``resp_bytes``
  are copied (the originals kept) to ``source.bytes``/``destination.bytes``/``source.packets``/
  ``destination.packets``/``client.bytes``/``server.bytes``; a ``conn_long`` interim row becomes log ``conn`` with
  ``zeek.conn.long`` set to "true". The sensor is ``node`` (``beat.name``, else ``host.name``, else "malcolm":
  logstash/pipelines/enrichment/97_arkimize.conf). Zeek logs Malcolm reads as text keep Zeek's text values
  (numbers, "T"/"F", comma-separated sets); logs it reads as JSON keep JSON types.
- ``elastic``: the Elastic Agent Zeek integration (elastic/integrations packages/zeek 5.0.1, Elastic License 2.0;
  data_stream/connection/elasticsearch/ingest_pipeline/default.yml at commit
  611fffe2ace9ff3ba385ef77233079df6e7b47eb) and the Filebeat zeek module (elastic/beats
  x-pack/filebeat/module/zeek/connection/config/connection.yml). ``event.dataset`` is ``zeek.<stream>``
  (``zeek.connection`` for conn). ECS fields first: ``source.address``/``source.ip``, ``source.port``, ``source.bytes``
  (= ``orig_ip_bytes``), ``source.packets`` (= ``orig_pkts``), ``network.transport`` (= ``proto``),
  ``network.protocol`` (= ``service``, unchanged), ``zeek.session_id`` and ``event.id`` (= ``uid``),
  ``event.duration`` in nanoseconds; the Zeek remainder stays under ``zeek.connection.*`` with ``conn_state``
  renamed ``state``. For ICMP the ports move to ``zeek.connection.icmp.type``/``.code``. ``orig_bytes``,
  ``resp_bytes`` and ``tunnel_parents`` are removed, so they survive only in the Zeek line kept in
  ``event.original``. The sensor is ``agent.name``, else ``host.name`` (the shipper's host).
- ``security_onion``: Security Onion 2.4 (Security-Onion-Solutions/securityonion branch 2.4/main). Its Elastic Agent
  policy sets ``event.module`` to "zeek" and ``data_stream.dataset`` to "zeek" (salt/elasticfleet/files/
  integrations-dynamic/grid-nodes_general/zeek-logs.json); each log's ingest pipeline sets ``event.dataset`` to the
  bare log name and the shared ``common`` pipeline (salt/elasticsearch/files/ingest-dynamic/common, commit
  742649a33797ceb85a111402fb48cd3839d2fcbb) then prefixes the module, so the indexed dataset is ``zeek.<log>`` (SO's
  own hunt queries in salt/soc/defaults.yaml read ``event.dataset:zeek.notice``); ``common`` also removes
  ``message2``, the parsed Zeek line, so a Zeek field no pipeline renames is not indexed. A bare log name with
  ``event.module`` "zeek" (a record that did not pass ``common``) is read as Security Onion too. Its ingest pipeline
  ``zeek.conn`` (salt/elasticsearch/files/ingest/zeek.conn, commit c29f11863e96b86540fae76386c5e5ec3b8fe7d4) renames
  ``duration`` to ``event.duration`` (seconds, unconverted), ``orig_bytes``/``resp_bytes`` to
  ``client.bytes``/``server.bytes``, ``orig_ip_bytes``/``resp_ip_bytes`` to ``client.ip_bytes``/``server.ip_bytes``,
  ``orig_pkts``/``resp_pkts`` to
  ``client.packets``/``server.packets``, ``conn_state`` to ``connection.state``, ``history`` to
  ``connection.history``, ``missed_bytes`` to ``connection.bytes.missed``, ``local_orig``/``local_resp`` to
  ``connection.local.originator``/``.responder``, ``tunnel_parents`` to ``log.id.tunnel_parents``, ``vlan`` to
  ``network.vlan.id`` and the JA4 fields to ``hash.ja4*``; ``zeek.common`` renames ``uid`` to ``log.id.uid``, the
  ``id.*`` fields to ``source.*``/``destination.*``, ``community_id`` to ``network.community_id`` (computed when
  absent) and sets ``observer.name`` from ``agent.name``.
- ``plain``: Zeek's own JSON (scripts/base/protocols/conn/main.zeek) shipped without a module, with literal dotted
  keys (``"id.orig_h"``). Nothing the shipper writes says it is Zeek, so a site declares it per target; the log name
  is Zeek's ``_path`` when present, else the declared one.

A log that is not in this catalog is counted as not normalized (a skip naming the log), never an error.

Path notation in the field tables: a dotted path into the record (literal dotted keys are found too); a
``original:`` prefix reads the Zeek line in ``event.original`` (Elastic keeps no other structured copy of those
fields); a ``:ns`` / ``:ms`` suffix gives the unit of a duration or time that is not in seconds.

The analyzer logs below conn: their native fields are Zeek's (zeek/zeek tag v8.0.0, commit
f07a59d32cbbefdd7706bbe47a053f350c36aed0: scripts/base/protocols/<log>/main.zeek, base/frameworks/{files,notice,
signatures,intel,tunnels}/main.zeek, base/frameworks/notice/weird.zeek, base/files/{x509,pe,hash,extract}/main.zeek,
base/protocols/ssl/files.zeek, base/protocols/http/entities.zeek, policy/protocols/ssl/validate-certs.zeek; the files
log of Zeek 5.0 and the x509 and ssl logs of Zeek 4.x at their tags), plus the JA3/JA3S and HASSH packages
(salesforce/ja3 zeek/ja3.zeek, ja3s.zeek; salesforce/hassh zeek/hassh.zeek) and FoxIO's JA4+ package. Where each
shipper puts them (each table below names the file):

- Malcolm at commit 541160e513de90ed4ea5af1d1ed7a8a64758bf8d: logstash/pipelines/zeek/10xx_zeek_<log>.conf (JSON
  renames and the text-log column lists), 1200_zeek_mutate.conf (the shared lifts above, plus: ``user`` to
  ``related.user``, ``fuid`` to ``zeek.fuid``, ``is_orig`` to ``network.is_orig``; per log, the ssl and x509 subject
  and issuer kept whole in ``*_full`` and split into objects, ssl ``ja4``/``ja4s`` moved to ``tls.client.ja4``/
  ``tls.server.ja4s``, the weird name moved to ``rule.name``, the signatures message moved to ``event.original`` and
  its note to ``rule.category``, http's ``url.full`` and ``url.password`` built with the password),
  1300_zeek_normalize.conf (intel's indicator to ``threat.indicator.name``, its type and matched types translated
  into ``threat.indicator.type``, files' ``source`` to ``file.source``), 1400_zeek_convert.conf (x509 validity, pe
  compile time and snmp up_since as ISO times).
- Elastic at commit 8518218716a47fdd55b5e766f15e9fed1e5c3fe2: packages/zeek/data_stream/<stream>/elasticsearch/
  ingest_pipeline/default.yml, fields/fields.yml and _dev/test/pipeline/test-<stream>.log-expected.json. Fields a
  pipeline does not rename stay under ``zeek.<stream>``.
- Security Onion at commit 742649a33797ceb85a111402fb48cd3839d2fcbb: salt/elasticsearch/files/ingest/zeek.<log>,
  zeek.common and zeek.common_ssl; only renamed fields are indexed (see above).

A shipper that publishes no pipeline for a log does not write it (``absent_shapes`` names why).
"""

from __future__ import annotations

from dataclasses import dataclass, field

MALCOLM, ELASTIC, SECURITY_ONION, PLAIN = "malcolm", "elastic", "security_onion", "plain"
SHAPES = (MALCOLM, ELASTIC, SECURITY_ONION, PLAIN)
SHAPE_NAMES = {MALCOLM: "Malcolm", ELASTIC: "Elastic", SECURITY_ONION: "Security Onion", PLAIN: "plain Zeek JSON"}

# Readers (zeek.py) for each kind of value. Zeek's types: addr, port, count, interval, string, bool, set[string],
# vector of string, time. "names" is a set (sorted, distinct), "list" a vector (Zeek's order kept); "text1" is a string
# a shipper may have split into a one-element list; "count_text" a count a shipper may have converted to text;
# "time" an absolute time (epoch seconds, or an ISO-8601 time a shipper converted it to); "hex" and "hexes" lowercase
# digests; "addresses" a set or vector of addresses in the order written; "seconds_list" a vector of intervals.
KINDS = frozenset({"ip", "port", "count", "seconds", "text", "flag", "services", "names", "mac", "list", "text1",
                   "count_text", "time", "hex", "hexes", "addresses", "seconds_list"})


@dataclass(frozen=True, eq=False)
class ZeekField:
    """One typed field of a Zeek log and where each shipper shape writes it. A shape missing from `paths` does not
    write the field at all (its value never reaches the index)."""
    typed: str
    native: str                                 # the Zeek field name, as Zeek's own JSON writes it
    kind: str
    paths: dict[str, tuple[str, ...]]           # shape -> candidate paths, the first one present wins

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"unknown Zeek field kind {self.kind!r}")
        unknown = set(self.paths) - set(SHAPES)
        if unknown:
            raise ValueError(f"unknown Zeek shipper shapes {sorted(unknown)}")


@dataclass(frozen=True, eq=False)
class ZeekLog:
    """One catalogued Zeek log: its family, its name in each shape, and its native-to-typed field table."""
    name: str                                   # Zeek's own log name (`_path`)
    family: str
    names: dict[str, frozenset[str]]            # shape -> the log names that shipper writes for it
    # shape -> where the shipper keeps the log's remaining native Zeek fields ("" for the record itself); a shape
    # that renames every field it keeps has none
    log_objects: dict[str, str]
    fields: tuple[ZeekField, ...]
    documentation_url: str
    sensor_paths: dict[str, tuple[str, ...]] = field(default_factory=dict)
    time_paths: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # The transport of the log's analyzer when Zeek's record has no proto of its own (HTTP runs over TCP only, SNMP
    # over UDP only); None when the record writes it or the analyzer reads more than one transport.
    transport: str | None = None
    # shape -> where the shipper writes a password value of this log: presence is typed, the value never read
    secrets: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # shape -> why the shipper writes no record of this log (it publishes no pipeline for it)
    absent_shapes: dict[str, str] = field(default_factory=dict)
    # typed fields naming the record within its connection or file, in order: its logical identity with the sensor,
    # the log, the time and the record's typed values
    key: tuple[str, ...] = ()
    sequence: tuple[str, ...] = ()

    @property
    def token(self) -> str:
        """The dispatch token: the bare names (`conn`, `dns`) collide with other datasets, this never does."""
        return f"zeek:{self.name}"

    def spec(self, typed: str) -> ZeekField:
        for item in self.fields:
            if item.typed == typed:
                return item
        raise KeyError(typed)


def _each(malcolm=(), elastic=(), security_onion=(), plain=()) -> dict[str, tuple[str, ...]]:
    return {shape: tuple(paths) for shape, paths in ((MALCOLM, malcolm), (ELASTIC, elastic),
                                                     (SECURITY_ONION, security_onion), (PLAIN, plain)) if paths}


def _f(typed: str, native: str, kind: str, **paths) -> ZeekField:
    return ZeekField(typed, native, kind, _each(**paths))


# Where each shape names its sensor, in order (`observer.name`; for plain Zeek JSON the site declares it), and the
# time of the record's first packet (Zeek's `ts`). A number in `@timestamp` is epoch milliseconds (the default date
# format of Elasticsearch and OpenSearch); Zeek's own `ts` is epoch seconds.
SENSOR_PATHS = _each(malcolm=("node",), elastic=("agent.name", "host.name"),
                     security_onion=("observer.name",))
TIME_PATHS = _each(malcolm=("@timestamp:ms", "firstPacket:ms"), elastic=("@timestamp:ms",),
                   security_onion=("@timestamp:ms",), plain=("ts",))

CONN_FIELDS = (
    _f("source.ip", "id.orig_h", "ip", malcolm=("source.ip",),
       elastic=("source.ip", "source.address", "zeek.connection.id.orig_h", "zeek.connection.orig_h"),
       security_onion=("source.ip",), plain=("id.orig_h",)),
    _f("source.port", "id.orig_p", "port", malcolm=("source.port",),
       elastic=("source.port", "zeek.connection.icmp.type", "zeek.connection.id.orig_p"),
       security_onion=("source.port",), plain=("id.orig_p",)),
    _f("destination.ip", "id.resp_h", "ip", malcolm=("destination.ip",),
       elastic=("destination.ip", "destination.address", "zeek.connection.id.resp_h", "zeek.connection.resp_h"),
       security_onion=("destination.ip",), plain=("id.resp_h",)),
    _f("destination.port", "id.resp_p", "port", malcolm=("destination.port",),
       elastic=("destination.port", "zeek.connection.icmp.code", "zeek.connection.id.resp_p"),
       security_onion=("destination.port",), plain=("id.resp_p",)),
    _f("network.transport", "proto", "text", malcolm=("network.transport",),
       elastic=("network.transport", "zeek.connection.proto"), security_onion=("network.transport",),
       plain=("proto",)),
    _f("network.iana_number", "ip_proto", "count", malcolm=("ipProtocol", "zeek.conn.ip_proto"),
       elastic=("zeek.connection.ip_proto",), plain=("ip_proto",)),
    _f("network.protocols", "service", "services", malcolm=("network.protocol",), elastic=("network.protocol",),
       security_onion=("network.protocol",), plain=("service",)),
    _f("zeek.uid", "uid", "text", malcolm=("zeek.uid",), elastic=("zeek.session_id", "event.id"),
       security_onion=("log.id.uid",), plain=("uid",)),
    _f("session.duration_s", "duration", "seconds", malcolm=("zeek.conn.duration",),
       elastic=("event.duration:ns", "zeek.connection.duration"), security_onion=("event.duration",),
       plain=("duration",)),
    # payload bytes, from TCP sequence numbers (Zeek: "might be inaccurate", for example on large connections)
    _f("flow.bytes_toserver", "orig_bytes", "count", malcolm=("zeek.conn.orig_bytes", "client.bytes"),
       elastic=("zeek.connection.orig_bytes", "original:orig_bytes"), security_onion=("client.bytes",),
       plain=("orig_bytes",)),
    _f("flow.bytes_toclient", "resp_bytes", "count", malcolm=("zeek.conn.resp_bytes", "server.bytes"),
       elastic=("zeek.connection.resp_bytes", "original:resp_bytes"), security_onion=("server.bytes",),
       plain=("resp_bytes",)),
    _f("flow.pkts_toserver", "orig_pkts", "count", malcolm=("zeek.conn.orig_pkts", "source.packets"),
       elastic=("source.packets", "zeek.connection.orig_pkts"), security_onion=("client.packets",),
       plain=("orig_pkts",)),
    _f("flow.pkts_toclient", "resp_pkts", "count", malcolm=("zeek.conn.resp_pkts", "destination.packets"),
       elastic=("destination.packets", "zeek.connection.resp_pkts"), security_onion=("server.packets",),
       plain=("resp_pkts",)),
    # IP-level bytes, from the IP total-length field: never the payload counts above
    _f("source.bytes", "orig_ip_bytes", "count", malcolm=("zeek.conn.orig_ip_bytes", "source.bytes"),
       elastic=("source.bytes", "zeek.connection.orig_ip_bytes"), security_onion=("client.ip_bytes",),
       plain=("orig_ip_bytes",)),
    _f("destination.bytes", "resp_ip_bytes", "count", malcolm=("zeek.conn.resp_ip_bytes", "destination.bytes"),
       elastic=("destination.bytes", "zeek.connection.resp_ip_bytes"), security_onion=("server.ip_bytes",),
       plain=("resp_ip_bytes",)),
    _f("conn.state", "conn_state", "text", malcolm=("zeek.conn.conn_state",),
       elastic=("zeek.connection.state", "zeek.connection.conn_state"), security_onion=("connection.state",),
       plain=("conn_state",)),
    _f("conn.history", "history", "text", malcolm=("zeek.conn.history",), elastic=("zeek.connection.history",),
       security_onion=("connection.history",), plain=("history",)),
    _f("conn.local_orig", "local_orig", "flag", malcolm=("zeek.conn.local_orig",),
       elastic=("zeek.connection.local_orig",), security_onion=("connection.local.originator",),
       plain=("local_orig",)),
    _f("conn.local_resp", "local_resp", "flag", malcolm=("zeek.conn.local_resp",),
       elastic=("zeek.connection.local_resp",), security_onion=("connection.local.responder",),
       plain=("local_resp",)),
    _f("conn.missed_bytes", "missed_bytes", "count", malcolm=("zeek.conn.missed_bytes",),
       elastic=("zeek.connection.missed_bytes",), security_onion=("connection.bytes.missed",),
       plain=("missed_bytes",)),
    _f("conn.tunnel_parents", "tunnel_parents", "names", malcolm=("zeek.conn.tunnel_parents",),
       elastic=("zeek.connection.tunnel_parents", "original:tunnel_parents"),
       security_onion=("log.id.tunnel_parents",), plain=("tunnel_parents",)),
    _f("network.community_id", "community_id", "text", malcolm=("network.community_id",),
       elastic=("network.community_id",), security_onion=("network.community_id",), plain=("community_id",)),
    _f("network.vlan.id", "vlan", "count", malcolm=("zeek.conn.vlan",), elastic=("zeek.connection.vlan",),
       security_onion=("network.vlan.id",), plain=("vlan",)),
    _f("network.inner.vlan.id", "inner_vlan", "count", malcolm=("zeek.conn.inner_vlan",),
       elastic=("zeek.connection.inner_vlan",), plain=("inner_vlan",)),
    _f("source.mac", "orig_l2_addr", "mac", malcolm=("source.mac",), elastic=("source.mac",),
       plain=("orig_l2_addr",)),
    _f("destination.mac", "resp_l2_addr", "mac", malcolm=("destination.mac",), elastic=("destination.mac",),
       plain=("resp_l2_addr",)),
    # JA4+ TCP and latency fingerprints from FoxIO's Zeek package (read only; computing them needs a licence review)
    _f("conn.ja4t", "ja4t", "text", malcolm=("zeek.conn.ja4t",), elastic=("zeek.connection.ja4t",),
       security_onion=("hash.ja4t",), plain=("ja4t",)),
    _f("conn.ja4ts", "ja4ts", "text", malcolm=("zeek.conn.ja4ts",), elastic=("zeek.connection.ja4ts",),
       security_onion=("hash.ja4ts",), plain=("ja4ts",)),
    _f("conn.ja4l", "ja4l", "text", malcolm=("zeek.conn.ja4l",), elastic=("zeek.connection.ja4l",),
       security_onion=("hash.ja4l",), plain=("ja4l",)),
    _f("conn.ja4ls", "ja4ls", "text", malcolm=("zeek.conn.ja4ls",), elastic=("zeek.connection.ja4ls",),
       security_onion=("hash.ja4ls",), plain=("ja4ls",)),
    # Malcolm's conn_long rows: interim records of a connection still open, written before its conn record
    _f("conn.interim", "long", "flag", malcolm=("zeek.conn.long",)),
)

CONN = ZeekLog(
    name="conn", family="net_flow",
    # plain `conn_long` is the interim log of Zeek's long-connections package (Malcolm renames it to conn itself)
    names={MALCOLM: frozenset({"conn"}), ELASTIC: frozenset({"connection", "conn"}),
           SECURITY_ONION: frozenset({"conn"}), PLAIN: frozenset({"conn", "conn_long"})},
    log_objects={MALCOLM: "zeek.conn", ELASTIC: "zeek.connection", PLAIN: ""},
    fields=CONN_FIELDS,
    documentation_url="https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html",
    sensor_paths=SENSOR_PATHS, time_paths=TIME_PATHS,
)

# ---- the analyzer logs -----------------------------------------------------------------------------------------------

def _log(name: str, family: str, fields: tuple[ZeekField, ...], *, elastic: str | None = None,
         so: str | None = None, absent: dict[str, str] | None = None, **extra) -> ZeekLog:
    """An analyzer log written by every shape except those in `absent`: Malcolm under ``zeek.<name>``, Elastic under
    ``zeek.<elastic stream>``, Security Onion as ``zeek.<so name>`` (renamed fields only), plain JSON as Zeek wrote it."""
    absent = absent or {}
    stream, so_name = elastic or name, so or name
    names = {MALCOLM: frozenset({name}), ELASTIC: frozenset({stream}), SECURITY_ONION: frozenset({so_name}),
             PLAIN: frozenset({name})}
    objects = {MALCOLM: f"zeek.{name}", ELASTIC: f"zeek.{stream}", PLAIN: ""}
    for shape in absent:
        names.pop(shape)
        objects.pop(shape, None)
    for item in fields:
        if set(item.paths) & set(absent):
            raise ValueError(f"{name}: {item.typed} has paths in a shape that does not write the log")
    doc = extra.pop("doc")
    url = doc if doc.startswith("https://") else f"https://docs.zeek.org/en/current/scripts/{doc}.html"
    return ZeekLog(name=name, family=family, names=names, log_objects=objects, fields=fields, documentation_url=url,
                   sensor_paths=SENSOR_PATHS, time_paths=TIME_PATHS, absent_shapes=absent, **extra)


def _endpoints(log: str, stream: str | None = None, *, absent=()) -> tuple[ZeekField, ...]:
    """The connection's addresses, ports, uid and Community ID on an analyzer log's record: Malcolm lifts them for
    every log, Elastic renames them to ECS (or leaves them, literal-dotted, under the stream's object), Security Onion's
    ``zeek.common`` renames them, plain JSON keeps Zeek's names."""
    el = f"zeek.{stream or log}"

    def paths(malcolm, elastic, so, plain):
        out = {"malcolm": malcolm, "elastic": elastic, "security_onion": so, "plain": plain}
        return {shape: value for shape, value in out.items() if shape not in absent}

    return (
        _f("source.ip", "id.orig_h", "ip", **paths(("source.ip",), ("source.ip", "source.address", f"{el}.id.orig_h"),
                                                    ("source.ip",), ("id.orig_h",))),
        _f("source.port", "id.orig_p", "port", **paths(("source.port",), ("source.port", f"{el}.id.orig_p"),
                                                        ("source.port",), ("id.orig_p",))),
        _f("destination.ip", "id.resp_h", "ip",
           **paths(("destination.ip",), ("destination.ip", "destination.address", f"{el}.id.resp_h"),
                   ("destination.ip",), ("id.resp_h",))),
        _f("destination.port", "id.resp_p", "port",
           **paths(("destination.port",), ("destination.port", f"{el}.id.resp_p"), ("destination.port",),
                   ("id.resp_p",))),
        _f("zeek.uid", "uid", "text", **paths(("zeek.uid",), ("zeek.session_id", "event.id", f"{el}.uid"),
                                               ("log.id.uid",), ("uid",))),
        _f("network.community_id", "community_id", "text",
           **paths(("network.community_id",), ("network.community_id",), ("network.community_id",),
                   ("community_id",))),
    )


def _proto(log: str, stream: str | None = None) -> ZeekField:
    return _f("network.transport", "proto", "text", malcolm=("network.transport",),
              elastic=("network.transport", f"zeek.{stream or log}.proto"), security_onion=("network.transport",),
              plain=("proto",))


# Malcolm lifts every log's `user` column to related.user (JSON http renames `username` to `user` first) and every
# `password` column to related.password; it builds http's url.password and url.full with that password, and its http
# extension adds post_password_* columns. None of these is ever read into a typed value (url.full is never read at
# all: Malcolm writes it on every http row, with or without a password).
MALCOLM_SECRETS = ("related.password", "url.password")

DNS = _log("dns", "dns_query", (
    *_endpoints("dns"), _proto("dns"),
    _f("dns.id", "trans_id", "count_text", malcolm=("zeek.dns.trans_id",),
       elastic=("zeek.dns.trans_id", "dns.id"), security_onion=("dns.id",), plain=("trans_id",)),
    _f("dns.rtt_s", "rtt", "seconds", malcolm=("zeek.dns.rtt",), elastic=("zeek.dns.rtt",),
       security_onion=("event.duration",), plain=("rtt",)),
    _f("dns.question.name", "query", "text", malcolm=("zeek.dns.query",), elastic=("zeek.dns.query",),
       security_onion=("dns.query.name",), plain=("query",)),
    _f("dns.question.class", "qclass_name", "text", malcolm=("zeek.dns.qclass_name",),
       elastic=("zeek.dns.qclass_name",), security_onion=("dns.query.class_name",), plain=("qclass_name",)),
    _f("zeek.dns.qtype", "qtype", "count", malcolm=("zeek.dns.qtype",), elastic=("zeek.dns.qtype",),
       security_onion=("dns.query.type",), plain=("qtype",)),
    _f("dns.question.type", "qtype_name", "text", malcolm=("zeek.dns.qtype_name",),
       elastic=("zeek.dns.qtype_name", "dns.question.type"), security_onion=("dns.query.type_name",),
       plain=("qtype_name",)),
    _f("zeek.dns.rcode", "rcode", "count", malcolm=("zeek.dns.rcode",), elastic=("zeek.dns.rcode",),
       security_onion=("dns.response.code",), plain=("rcode",)),
    _f("dns.response_code", "rcode_name", "text", malcolm=("zeek.dns.rcode_name",),
       elastic=("zeek.dns.rcode_name", "dns.response_code"), security_onion=("dns.response.code_name",),
       plain=("rcode_name",)),
    *(_f(f"zeek.dns.{flag}", flag, "flag", malcolm=(f"zeek.dns.{flag}",), elastic=(f"zeek.dns.{flag}",),
         security_onion=(so,), plain=(flag,))
      for flag, so in (("AA", "dns.authoritative"), ("TC", "dns.truncated"), ("RD", "dns.recursion.desired"),
                       ("RA", "dns.recursion.available"))),
    _f("zeek.dns.answers", "answers", "list", malcolm=("zeek.dns.answers",), elastic=("zeek.dns.answers",),
       security_onion=("dns.answers.name",), plain=("answers",)),
    _f("dns.ttls", "TTLs", "seconds_list", malcolm=("zeek.dns.TTLs",), elastic=("zeek.dns.TTLs",),
       security_onion=("dns.ttls",), plain=("TTLs",)),
    _f("dns.rejected", "rejected", "flag", malcolm=("zeek.dns.rejected",), elastic=("zeek.dns.rejected",),
       security_onion=("dns.query.rejected",), plain=("rejected",)),
), doc="base/protocols/dns/main.zeek", key=("zeek.uid",), sequence=("dns.id",))

HTTP = _log("http", "http_tx", (
    *_endpoints("http"),
    _f("http.trans_depth", "trans_depth", "count", malcolm=("zeek.http.trans_depth",),
       elastic=("zeek.http.trans_depth",), security_onion=("http.trans_depth",), plain=("trans_depth",)),
    _f("http.request.method", "method", "text", malcolm=("zeek.http.method",), elastic=("http.request.method",),
       security_onion=("http.method",), plain=("method",)),
    # Elastic moves the host to url.domain when its uri_parts left that empty, and drops it when equal to it
    _f("http.hostname", "host", "text", malcolm=("zeek.http.host",), elastic=("zeek.http.host", "url.domain"),
       security_onion=("http.virtual_host",), plain=("host",)),
    # Elastic parses the uri with uri_parts (keeping it in url.original) and removes zeek.http.uri; Malcolm's own
    # url.original is "http://" + host + uri, so it is not read
    _f("url.original", "uri", "text", malcolm=("zeek.http.uri",), elastic=("url.original",),
       security_onion=("http.uri",), plain=("uri",)),
    _f("http.request.referrer", "referrer", "text", malcolm=("zeek.http.referrer",),
       elastic=("http.request.referrer",), security_onion=("http.referrer",), plain=("referrer",)),
    _f("http.version", "version", "text", malcolm=("zeek.http.version",), elastic=("http.version",),
       security_onion=("http.version",), plain=("version",)),
    _f("user_agent.original", "user_agent", "text", malcolm=("zeek.http.user_agent",),
       elastic=("user_agent.original",), security_onion=("http.useragent",), plain=("user_agent",)),
    _f("http.request.origin", "origin", "text", malcolm=("zeek.http.origin",), elastic=("zeek.http.origin",),
       plain=("origin",)),
    _f("http.request.body.bytes", "request_body_len", "count", malcolm=("zeek.http.request_body_len",),
       elastic=("http.request.body.bytes",), security_onion=("http.request.body.length",),
       plain=("request_body_len",)),
    _f("http.response.body.bytes", "response_body_len", "count", malcolm=("zeek.http.response_body_len",),
       elastic=("http.response.body.bytes",), security_onion=("http.response.body.length",),
       plain=("response_body_len",)),
    _f("http.response.status_code", "status_code", "count", malcolm=("zeek.http.status_code",),
       elastic=("http.response.status_code",), security_onion=("http.status_code",), plain=("status_code",)),
    _f("http.response.status_message", "status_msg", "text", malcolm=("zeek.http.status_msg",),
       elastic=("zeek.http.status_msg",), security_onion=("http.status_message",), plain=("status_msg",)),
    _f("http.info_code", "info_code", "count", malcolm=("zeek.http.info_code",), elastic=("zeek.http.info_code",),
       security_onion=("http.info_code",), plain=("info_code",)),
    _f("http.info_message", "info_msg", "text", malcolm=("zeek.http.info_msg",), elastic=("zeek.http.info_msg",),
       security_onion=("http.info_message",), plain=("info_msg",)),
    # Zeek sets the username only from an Authorization or Proxy-Authorization header of the Basic scheme
    _f("user.name", "username", "text1", malcolm=("related.user",), elastic=("url.username", "user.name"),
       security_onion=("http.user",), plain=("username",)),
    *(_f(f"http.{name}", name, kind, malcolm=(f"zeek.http.{name}",), elastic=(f"zeek.http.{name}",),
         security_onion=(so,), plain=(name,))
      for name, kind, so in (("orig_fuids", "list", "log.id.orig_fuids"),
                             ("orig_filenames", "list", "file.orig_filenames"),
                             ("orig_mime_types", "list", "file.orig_mime_types"),
                             ("resp_fuids", "list", "log.id.resp_fuids"),
                             ("resp_filenames", "list", "file.resp_filenames"),
                             ("resp_mime_types", "list", "file.resp_mime_types"))),
    _f("http.ja4h", "ja4h", "text", malcolm=("zeek.http.ja4h",), elastic=("zeek.http.ja4h",),
       security_onion=("hash.ja4h",), plain=("ja4h",)),
), doc="base/protocols/http/main.zeek", transport="tcp", key=("zeek.uid",), sequence=("http.trans_depth",),
    secrets={MALCOLM: (*MALCOLM_SECRETS, "zeek.http.post_password_plain", "zeek.http.post_password_md5",
                       "zeek.http.post_password_sha1", "zeek.http.post_password_sha256"),
             ELASTIC: ("url.password", "zeek.http.password"), SECURITY_ONION: ("http.password",),
             PLAIN: ("password",)})

SSL = _log("ssl", "tls_session", (
    *_endpoints("ssl"),
    _f("zeek.ssl.version", "version", "text", malcolm=("zeek.ssl.ssl_version",), elastic=("zeek.ssl.version",),
       security_onion=("ssl.version",), plain=("version",)),
    _f("tls.cipher", "cipher", "text", malcolm=("zeek.ssl.cipher",), elastic=("zeek.ssl.cipher", "tls.cipher"),
       security_onion=("ssl.cipher",), plain=("cipher",)),
    _f("tls.curve", "curve", "text", malcolm=("zeek.ssl.curve",), elastic=("zeek.ssl.curve", "tls.curve"),
       security_onion=("ssl.curve",), plain=("curve",)),
    _f("tls.client.server_name", "server_name", "text", malcolm=("zeek.ssl.server_name",),
       elastic=("zeek.ssl.server.name",), security_onion=("ssl.server_name",), plain=("server_name",)),
    _f("tls.resumed", "resumed", "flag", malcolm=("zeek.ssl.resumed",), elastic=("zeek.ssl.resumed",),
       security_onion=("ssl.resumed",), plain=("resumed",)),
    _f("tls.established", "established", "flag", malcolm=("zeek.ssl.established",),
       elastic=("zeek.ssl.established",), security_onion=("ssl.established",), plain=("established",)),
    _f("tls.last_alert", "last_alert", "text", malcolm=("zeek.ssl.last_alert",), elastic=("zeek.ssl.last_alert",),
       security_onion=("ssl.last_alert",), plain=("last_alert",)),
    _f("tls.next_protocol", "next_protocol", "text", malcolm=("zeek.ssl.next_protocol",),
       elastic=("zeek.ssl.next_protocol",), security_onion=("ssl.next_protocol",), plain=("next_protocol",)),
    _f("tls.ssl_history", "ssl_history", "text", malcolm=("zeek.ssl.ssl_history",),
       elastic=("zeek.ssl.ssl_history",), plain=("ssl_history",)),
    _f("tls.validation_status", "validation_status", "text", malcolm=("zeek.ssl.validation_status",),
       elastic=("zeek.ssl.validation.status",), security_onion=("ssl.validation_status",),
       plain=("validation_status",)),
    _f("tls.sni_matches_cert", "sni_matches_cert", "flag", malcolm=("zeek.ssl.sni_matches_cert",),
       elastic=("zeek.ssl.sni_matches_cert",), plain=("sni_matches_cert",)),
    # Zeek 4.2 and later: the SHA-256 fingerprints of the chain (the x509 log's `fingerprint`); before: file ids
    _f("tls.server.cert_chain_fps", "cert_chain_fps", "list", malcolm=("zeek.ssl.cert_chain_fps",),
       elastic=("zeek.ssl.cert_chain_fps",), security_onion=("tls.server.hash.sha256",), plain=("cert_chain_fps",)),
    _f("tls.client.cert_chain_fps", "client_cert_chain_fps", "list", malcolm=("zeek.ssl.client_cert_chain_fps",),
       elastic=("zeek.ssl.client_cert_chain_fps",), security_onion=("tls.client.hash.sha256",),
       plain=("client_cert_chain_fps",)),
    _f("tls.server.cert_chain_fuids", "cert_chain_fuids", "list", malcolm=("zeek.ssl.cert_chain_fuids",),
       elastic=("zeek.ssl.server.cert_chain_fuids",), security_onion=("ssl.certificate.chain_fuids",),
       plain=("cert_chain_fuids",)),
    _f("tls.client.cert_chain_fuids", "client_cert_chain_fuids", "list",
       malcolm=("zeek.ssl.client_cert_chain_fuids",), elastic=("zeek.ssl.client.cert_chain_fuids",),
       security_onion=("ssl.client.certificate.chain_fuids",), plain=("client_cert_chain_fuids",)),
    # the server's (first) certificate's names; Malcolm keeps the whole name in *_full and splits the original,
    # Elastic moves it to tls.server.* (and keeps the client subject only split, so it is read from the Zeek line)
    _f("zeek.ssl.subject", "subject", "text", malcolm=("zeek.ssl.subject_full",), elastic=("tls.server.subject",),
       security_onion=("ssl.certificate.subject",), plain=("subject",)),
    _f("zeek.ssl.issuer", "issuer", "text", malcolm=("zeek.ssl.issuer_full",), elastic=("tls.server.issuer",),
       security_onion=("ssl.certificate.issuer",), plain=("issuer",)),
    _f("tls.client.subject", "client_subject", "text", malcolm=("zeek.ssl.client_subject_full",),
       elastic=("original:client_subject",), security_onion=("ssl.client.subject",), plain=("client_subject",)),
    _f("tls.client.issuer", "client_issuer", "text", malcolm=("zeek.ssl.client_issuer_full",),
       elastic=("tls.client.issuer",), security_onion=("ssl.client.issuer",), plain=("client_issuer",)),
    _f("tls.ja3", "ja3", "hexes", malcolm=("zeek.ssl.ja3", "tls.client.ja3"), elastic=("tls.client.ja3",),
       security_onion=("hash.ja3",), plain=("ja3",)),
    _f("tls.ja3s", "ja3s", "hexes", malcolm=("zeek.ssl.ja3s", "tls.server.ja3s"), elastic=("tls.server.ja3s",),
       security_onion=("hash.ja3s",), plain=("ja3s",)),
    _f("tls.ja4", "ja4", "list", malcolm=("tls.client.ja4",), elastic=("zeek.ssl.ja4", "tls.client.ja4"),
       security_onion=("hash.ja4",), plain=("ja4",)),
    _f("tls.ja4s", "ja4s", "list", malcolm=("tls.server.ja4s",), elastic=("zeek.ssl.ja4s", "tls.server.ja4s"),
       security_onion=("hash.ja4s",), plain=("ja4s",)),
), doc="base/protocols/ssl/main.zeek", key=("zeek.uid",))

X509 = _log("x509", "x509_certificate", (
    _f("x509.fingerprint", "fingerprint", "text1", malcolm=("zeek.x509.fingerprint",),
       elastic=("zeek.x509.fingerprint",), security_onion=("hash.sha256",), plain=("fingerprint",)),
    # Zeek before 4.2 keyed the row by its file id (`id`); Elastic renames that to zeek.session_id
    _f("file.fuid", "id", "text1", malcolm=("zeek.fuid", "zeek.x509.id"), elastic=("zeek.session_id",),
       security_onion=("log.id.fuid",), plain=("id",)),
    _f("x509.version", "certificate.version", "count", malcolm=("zeek.x509.certificate_version",),
       elastic=("zeek.x509.certificate.version",), security_onion=("x509.certificate.version",),
       plain=("certificate.version",)),
    _f("x509.serial", "certificate.serial", "hex", malcolm=("zeek.x509.certificate_serial",),
       elastic=("zeek.x509.certificate.serial",), security_onion=("x509.certificate.serial",),
       plain=("certificate.serial",)),
    # Elastic splits the names into objects and keeps no whole copy outside its Zeek line
    _f("x509.subject", "certificate.subject", "text", malcolm=("zeek.x509.certificate_subject_full",),
       elastic=("original:certificate.subject",), security_onion=("x509.certificate.subject",),
       plain=("certificate.subject",)),
    _f("x509.issuer", "certificate.issuer", "text", malcolm=("zeek.x509.certificate_issuer_full",),
       elastic=("original:certificate.issuer",), security_onion=("x509.certificate.issuer",),
       plain=("certificate.issuer",)),
    _f("x509.not_before", "certificate.not_valid_before", "time",
       malcolm=("zeek.x509.certificate_not_valid_before",), elastic=("zeek.x509.certificate.valid.from",),
       security_onion=("x509.certificate.not_valid_before",), plain=("certificate.not_valid_before",)),
    _f("x509.not_after", "certificate.not_valid_after", "time", malcolm=("zeek.x509.certificate_not_valid_after",),
       elastic=("zeek.x509.certificate.valid.until",), security_onion=("x509.certificate.not_valid_after",),
       plain=("certificate.not_valid_after",)),
    _f("x509.key_algorithm", "certificate.key_alg", "text", malcolm=("zeek.x509.certificate_key_alg",),
       elastic=("zeek.x509.certificate.key.algorithm",), security_onion=("x509.certificate.key.algorithm",),
       plain=("certificate.key_alg",)),
    _f("x509.signature_algorithm", "certificate.sig_alg", "text", malcolm=("zeek.x509.certificate_sig_alg",),
       elastic=("zeek.x509.certificate.signature_algorithm",),
       security_onion=("x509.certificate.signing_algorithm",), plain=("certificate.sig_alg",)),
    _f("x509.key_type", "certificate.key_type", "text", malcolm=("zeek.x509.certificate_key_type",),
       elastic=("zeek.x509.certificate.key.type",), security_onion=("x509.certificate.key.type",),
       plain=("certificate.key_type",)),
    _f("x509.key_length", "certificate.key_length", "count", malcolm=("zeek.x509.certificate_key_length",),
       elastic=("zeek.x509.certificate.key.length",), security_onion=("x509.certificate.key.length",),
       plain=("certificate.key_length",)),
    _f("x509.exponent", "certificate.exponent", "text", malcolm=("zeek.x509.certificate_exponent",),
       elastic=("zeek.x509.certificate.exponent",), security_onion=("x509.certificate.exponent",),
       plain=("certificate.exponent",)),
    _f("x509.curve", "certificate.curve", "text", malcolm=("zeek.x509.certificate_curve",),
       elastic=("zeek.x509.certificate.curve",), security_onion=("x509.certificate.curve",),
       plain=("certificate.curve",)),
    *(_f(f"x509.san_{part}", f"san.{part}", "addresses" if part == "ip" else "list",
         malcolm=(f"zeek.x509.san_{part}",), elastic=(f"zeek.x509.san.{part}",),
         security_onion=(f"x509.san_{part}",), plain=(f"san.{part}",))
      for part in ("dns", "uri", "email", "ip")),
    _f("x509.basic_constraints.ca", "basic_constraints.ca", "flag", malcolm=("zeek.x509.basic_constraints_ca",),
       elastic=("zeek.x509.basic_constraints.certificate_authority",),
       security_onion=("x509.basic_constraints.ca",), plain=("basic_constraints.ca",)),
    # Security Onion renames basic_constraints.path_length, a name Zeek does not write: path_len is not indexed
    _f("x509.basic_constraints.path_len", "basic_constraints.path_len", "count",
       malcolm=("zeek.x509.basic_constraints_path_len",), elastic=("zeek.x509.basic_constraints.path_length",),
       plain=("basic_constraints.path_len",)),
    _f("x509.host_cert", "host_cert", "flag", malcolm=("zeek.x509.host_cert",), elastic=("zeek.x509.host_cert",),
       plain=("host_cert",)),
    _f("x509.client_cert", "client_cert", "flag", malcolm=("zeek.x509.client_cert",),
       elastic=("zeek.x509.client_cert",), plain=("client_cert",)),
), doc="base/files/x509/main.zeek", key=("x509.fingerprint", "file.fuid"))

FILES = _log("files", "file_transfer", (
    # Zeek 5.1 and later write one connection per row (uid, id.*); Elastic leaves them, literal-dotted, under
    # zeek.files (no pipeline step reads them: unverified against a live index). Security Onion writes Zeek 5.0's
    # first sending and receiving hosts to source.ip and destination.ip: zeek.py tells the two layouts apart.
    *(spec for spec in _endpoints("files") if spec.typed != "zeek.uid"),
    _f("zeek.uid", "uid", "text", malcolm=("zeek.uid",), elastic=("zeek.files.uid",), plain=("uid",)),
    _f("file.fuid", "fuid", "text1", malcolm=("zeek.fuid",), elastic=("zeek.files.fuid",),
       security_onion=("log.id.fuid",), plain=("fuid",)),
    # Zeek 5.0 and earlier: the sets of connections and of sending and receiving hosts. Elastic keeps only the first
    # host of each set (zeek.files.tx_host, rx_host); Security Onion's copies are read in zeek.py.
    _f("file.conn_uids", "conn_uids", "names", malcolm=("zeek.files.conn_uids",),
       elastic=("zeek.files.session_ids",), plain=("conn_uids",)),
    _f("file.tx_hosts", "tx_hosts", "addresses", malcolm=("zeek.files.tx_hosts",),
       elastic=("zeek.files.tx_host",), plain=("tx_hosts",)),
    _f("file.rx_hosts", "rx_hosts", "addresses", malcolm=("zeek.files.rx_hosts",),
       elastic=("zeek.files.rx_host",), plain=("rx_hosts",)),
    _f("file.source", "source", "text", malcolm=("file.source", "zeek.files.source"),
       elastic=("zeek.files.source",), security_onion=("file.source",), plain=("source",)),
    _f("file.depth", "depth", "count", malcolm=("zeek.files.depth",), elastic=("zeek.files.depth",),
       security_onion=("file.depth",), plain=("depth",)),
    _f("file.analyzers", "analyzers", "names", malcolm=("zeek.files.analyzers",), elastic=("zeek.files.analyzers",),
       security_onion=("file.analyzer",), plain=("analyzers",)),
    _f("file.mime_type", "mime_type", "text", malcolm=("zeek.files.mime_type",),
       elastic=("zeek.files.mime_type", "file.mime_type"), security_onion=("file.mime_type",),
       plain=("mime_type",)),
    _f("file.name", "filename", "text", malcolm=("zeek.files.filename",), elastic=("file.name",),
       security_onion=("file.name",), plain=("filename",)),
    _f("file.duration_s", "duration", "seconds", malcolm=("zeek.files.duration",), elastic=("zeek.files.duration",),
       security_onion=("event.duration",), plain=("duration",)),
    _f("file.local_orig", "local_orig", "flag", malcolm=("zeek.files.local_orig",),
       elastic=("zeek.files.local_orig",), security_onion=("file.local_orig",), plain=("local_orig",)),
    _f("file.is_orig", "is_orig", "flag", malcolm=("network.is_orig",), elastic=("zeek.files.is_orig",),
       security_onion=("file.is_orig",), plain=("is_orig",)),
    _f("file.seen_bytes", "seen_bytes", "count", malcolm=("zeek.files.seen_bytes",),
       elastic=("zeek.files.seen_bytes",), security_onion=("file.bytes.seen",), plain=("seen_bytes",)),
    _f("file.total_bytes", "total_bytes", "count", malcolm=("zeek.files.total_bytes",), elastic=("file.size",),
       security_onion=("file.bytes.total",), plain=("total_bytes",)),
    _f("file.missing_bytes", "missing_bytes", "count", malcolm=("zeek.files.missing_bytes",),
       elastic=("zeek.files.missing_bytes",), security_onion=("file.bytes.missing",), plain=("missing_bytes",)),
    _f("file.overflow_bytes", "overflow_bytes", "count", malcolm=("zeek.files.overflow_bytes",),
       elastic=("zeek.files.overflow_bytes",), security_onion=("file.bytes.overflow",), plain=("overflow_bytes",)),
    _f("file.timedout", "timedout", "flag", malcolm=("zeek.files.timedout",), elastic=("zeek.files.timedout",),
       security_onion=("file.timed_out",), plain=("timedout",)),
    _f("file.parent_fuid", "parent_fuid", "text1", malcolm=("zeek.files.parent_fuid",),
       elastic=("zeek.files.parent_fuid",), security_onion=("log.id.parent_fuid",), plain=("parent_fuid",)),
    _f("file.hash.md5", "md5", "hex", malcolm=("zeek.files.md5",), elastic=("zeek.files.md5", "file.hash.md5"),
       security_onion=("hash.md5",), plain=("md5",)),
    _f("file.hash.sha1", "sha1", "hex", malcolm=("zeek.files.sha1",), elastic=("zeek.files.sha1", "file.hash.sha1"),
       security_onion=("hash.sha1",), plain=("sha1",)),
    # Security Onion renames md5 and sha1 only: sha256 is not indexed
    _f("file.hash.sha256", "sha256", "hex", malcolm=("zeek.files.sha256",),
       elastic=("zeek.files.sha256", "file.hash.sha256"), plain=("sha256",)),
    _f("file.extracted", "extracted", "text", malcolm=("zeek.files.extracted",), elastic=("zeek.files.extracted",),
       security_onion=("file.extracted.filename",), plain=("extracted",)),
    _f("file.extracted_cutoff", "extracted_cutoff", "flag", malcolm=("zeek.files.extracted_cutoff",),
       elastic=("zeek.files.extracted_cutoff",), security_onion=("file.extracted.cutoff",),
       plain=("extracted_cutoff",)),
    _f("file.extracted_size", "extracted_size", "count", malcolm=("zeek.files.extracted_size",),
       elastic=("zeek.files.extracted_size",), security_onion=("file.extracted.size",), plain=("extracted_size",)),
), so="file", doc="base/frameworks/files/main.zeek", key=("file.fuid",))

_PE_FLAGS = (("is_exe", "file.is_exe"), ("is_64bit", "file.is_64bit"), ("uses_aslr", "file.aslr"),
             ("uses_dep", "file.dep"), ("uses_code_integrity", "file.code_integrity"), ("uses_seh", "file.seh"),
             ("has_import_table", "file.table.import"), ("has_export_table", "file.table.export"),
             ("has_cert_table", "file.table.cert"), ("has_debug_data", "file.debug_data"))
PE = _log("pe", "file_transfer", (
    _f("file.fuid", "id", "text1", malcolm=("zeek.fuid", "zeek.pe.id"), elastic=("zeek.pe.id",),
       security_onion=("log.id.fuid",), plain=("id",)),
    _f("pe.machine", "machine", "text", malcolm=("zeek.pe.machine",), elastic=("zeek.pe.machine",),
       security_onion=("file.machine",), plain=("machine",)),
    _f("pe.compile_ts", "compile_ts", "time", malcolm=("zeek.pe.compile_ts",), elastic=("zeek.pe.compile_time",),
       security_onion=("file.compile_timestamp",), plain=("compile_ts",)),
    _f("pe.os", "os", "text", malcolm=("zeek.pe.os",), elastic=("zeek.pe.os",), security_onion=("file.os",),
       plain=("os",)),
    _f("pe.subsystem", "subsystem", "text", malcolm=("zeek.pe.subsystem",), elastic=("zeek.pe.subsystem",),
       security_onion=("file.subsystem",), plain=("subsystem",)),
    *(_f(f"pe.{name}", name, "flag", malcolm=(f"zeek.pe.{name}",), elastic=(f"zeek.pe.{name}",),
         security_onion=(so,), plain=(name,)) for name, so in _PE_FLAGS),
    _f("pe.section_names", "section_names", "list", malcolm=("zeek.pe.section_names",),
       elastic=("zeek.pe.section_names",), security_onion=("file.section_names",), plain=("section_names",)),
), doc="base/files/pe/main.zeek", key=("file.fuid",))

SSH = _log("ssh", "ssh_session", (
    *_endpoints("ssh"),
    _f("ssh.protocol_version", "version", "count", malcolm=("zeek.ssh.version",), elastic=("zeek.ssh.version",),
       security_onion=("ssh.version",), plain=("version",)),
    _f("ssh.auth_success", "auth_success", "flag", malcolm=("zeek.ssh.auth_success",),
       elastic=("zeek.ssh.auth.success",), security_onion=("ssh.authentication.success",),
       plain=("auth_success",)),
    _f("ssh.auth_attempts", "auth_attempts", "count", malcolm=("zeek.ssh.auth_attempts",),
       elastic=("zeek.ssh.auth.attempts",), security_onion=("ssh.authentication.attempts",),
       plain=("auth_attempts",)),
    _f("ssh.direction", "direction", "text", malcolm=("zeek.ssh.direction",), elastic=("zeek.ssh.direction",),
       security_onion=("ssh.direction",), plain=("direction",)),
    _f("ssh.client.banner", "client", "text", malcolm=("zeek.ssh.client",), elastic=("zeek.ssh.client",),
       security_onion=("ssh.client",), plain=("client",)),
    _f("ssh.server.banner", "server", "text", malcolm=("zeek.ssh.server",), elastic=("zeek.ssh.server",),
       security_onion=("ssh.server",), plain=("server",)),
    *(_f(f"ssh.{name}_algorithm", f"{native}_alg", "text", malcolm=(f"zeek.ssh.{native}_alg",),
         elastic=(f"zeek.ssh.algorithm.{elastic}",), security_onion=(f"ssh.{so}_algorithm",),
         plain=(f"{native}_alg",))
      for name, native, elastic, so in (("cipher", "cipher", "cipher", "cipher"), ("mac", "mac", "mac", "mac"),
                                        ("compression", "compression", "compression", "compression"),
                                        ("kex", "kex", "key_exchange", "kex"),
                                        ("host_key", "host_key", "host_key", "host_key"))),
    _f("ssh.host_key", "host_key", "text", malcolm=("zeek.ssh.host_key", "zeek.ssh.host_key_fingerprint"),
       elastic=("zeek.ssh.host_key",), security_onion=("ssh.host_key",), plain=("host_key",)),
    _f("ssh.hassh", "hassh", "hexes", malcolm=("zeek.ssh.hassh",), elastic=("zeek.ssh.hassh",),
       security_onion=("hash.hassh",), plain=("hassh",)),
    _f("ssh.hassh_server", "hasshServer", "hexes", malcolm=("zeek.ssh.hasshServer",),
       elastic=("zeek.ssh.hasshServer",), security_onion=("ssh.hassh_server",), plain=("hasshServer",)),
), doc="base/protocols/ssh/main.zeek", transport="tcp", key=("zeek.uid",))

NOTICE = _log("notice", "net_alert", (
    # Zeek fills src/dst/p from the connection when the notice has one, and a notice without one names its addresses
    # there only; Elastic moves them to source/destination. Malcolm parses an ATTACK notice's message for addresses
    # into source.ip/destination.ip when the row has none, so its addresses are read from Zeek's src/dst only.
    *(spec for spec in _endpoints("notice") if spec.typed not in ("source.ip", "destination.ip",
                                                                   "destination.port")),
    _f("source.ip", "id.orig_h", "ip", malcolm=("zeek.notice.src",), elastic=("source.ip", "source.address"),
       security_onion=("source.ip",), plain=("id.orig_h", "src")),
    _f("destination.ip", "id.resp_h", "ip", malcolm=("zeek.notice.dst",),
       elastic=("destination.ip", "destination.address"), security_onion=("destination.ip",),
       plain=("id.resp_h", "dst")),
    _f("destination.port", "id.resp_p", "port", malcolm=("zeek.notice.p", "destination.port"),
       elastic=("destination.port",), security_onion=("destination.port", "notice.p"), plain=("id.resp_p", "p")),
    _proto("notice"),
    _f("alert.signature", "note", "text", malcolm=("zeek.notice.note",), elastic=("zeek.notice.note", "rule.name"),
       security_onion=("notice.note",), plain=("note",)),
    _f("alert.message", "msg", "text", malcolm=("zeek.notice.msg",),
       elastic=("zeek.notice.msg", "rule.description"), security_onion=("notice.message",), plain=("msg",)),
    _f("alert.sub_message", "sub", "text", malcolm=("zeek.notice.sub",), elastic=("zeek.notice.sub",),
       security_onion=("notice.sub_message",), plain=("sub",)),
    _f("notice.actions", "actions", "names", malcolm=("zeek.notice.actions",), elastic=("zeek.notice.actions",),
       security_onion=("notice.action",), plain=("actions",)),
    _f("file.fuid", "fuid", "text1", malcolm=("zeek.fuid",), elastic=("zeek.notice.fuid",),
       security_onion=("log.id.fuid",), plain=("fuid",)),
), doc="base/frameworks/notice/main.zeek", key=("zeek.uid",), sequence=("alert.signature",))

WEIRD = _log("weird", "net_alert", (
    *_endpoints("weird"),
    # Malcolm moves the name to rule.name (as a list whose first value is the name) and removes peer
    _f("alert.signature", "name", "text1", malcolm=("rule.name",), elastic=("zeek.weird.name",),
       security_onion=("weird.name",), plain=("name",)),
    _f("alert.message", "addl", "text", malcolm=("zeek.weird.addl",), elastic=("zeek.weird.additional_info",),
       security_onion=("weird.additional_info",), plain=("addl",)),
    _f("weird.notice", "notice", "flag", malcolm=("zeek.weird.notice",), elastic=("zeek.weird.notice",),
       security_onion=("weird.notice",), plain=("notice",)),
    _f("weird.peer", "peer", "text", elastic=("zeek.weird.peer",), security_onion=("weird.peer",),
       plain=("peer",)),
    _f("weird.source", "source", "text", malcolm=("zeek.weird.source",), elastic=("zeek.weird.source",),
       plain=("source",)),
), doc="base/frameworks/notice/weird.zeek", key=("zeek.uid",), sequence=("alert.signature",))

SIGNATURES = _log("signatures", "net_alert", (
    _f("source.ip", "src_addr", "ip", malcolm=("source.ip",), elastic=("source.ip", "source.address"),
       plain=("src_addr",)),
    _f("source.port", "src_port", "port", malcolm=("source.port", "zeek.signatures.src_port"),
       elastic=("source.port",), plain=("src_port",)),
    _f("destination.ip", "dst_addr", "ip", malcolm=("destination.ip",),
       elastic=("destination.ip", "destination.address"), plain=("dst_addr",)),
    _f("destination.port", "dst_port", "port", malcolm=("destination.port", "zeek.signatures.dst_port"),
       elastic=("destination.port",), plain=("dst_port",)),
    _f("zeek.uid", "uid", "text", malcolm=("zeek.uid",), elastic=("zeek.session_id", "event.id"),
       security_onion=("log.id.uid",), plain=("uid",)),
    _f("network.community_id", "community_id", "text", malcolm=("network.community_id",),
       elastic=("network.community_id",), security_onion=("network.community_id",), plain=("community_id",)),
    _f("alert.signature", "sig_id", "text", malcolm=("zeek.signatures.signature_id",), elastic=("rule.id",),
       security_onion=("signature_id",), plain=("sig_id",)),
    # Malcolm moves the message to event.original (as the message itself, not a Zeek line)
    _f("alert.message", "event_msg", "text", malcolm=("event.original",), elastic=("rule.description",),
       security_onion=("event_message",), plain=("event_msg",)),
    _f("alert.sub_message", "sub_msg", "text", malcolm=("zeek.signatures.sub_message",),
       elastic=("zeek.signature.sub_msg",), security_onion=("sub_message",), plain=("sub_msg",)),
    _f("alert.note", "note", "text1", malcolm=("rule.category",), elastic=("zeek.signature.note",),
       security_onion=("note",), plain=("note",)),
    _f("signature.count", "sig_count", "count", malcolm=("zeek.signatures.signature_count",),
       elastic=("zeek.signature.sig_count",), security_onion=("signature_count",), plain=("sig_count",)),
    _f("signature.host_count", "host_count", "count", malcolm=("zeek.signatures.host_count",),
       elastic=("zeek.signature.host_count",), security_onion=("host.count",), plain=("host_count",)),
), elastic="signature", doc="base/frameworks/signatures/main.zeek", key=("zeek.uid",),
    sequence=("alert.signature",))

INTEL = _log("intel", "net_alert", (
    *_endpoints("intel"),
    _f("intel.indicator", "seen.indicator", "text", malcolm=("threat.indicator.name",),
       elastic=("zeek.intel.seen.indicator",), security_onion=("intel.indicator",), plain=("seen.indicator",)),
    # Malcolm translates the indicator types into threat.indicator.type with its own table: not read
    _f("intel.indicator_type", "seen.indicator_type", "text", elastic=("zeek.intel.seen.indicator_type",),
       security_onion=("intel.indicator_type",), plain=("seen.indicator_type",)),
    _f("intel.seen_where", "seen.where", "text", malcolm=("zeek.intel.seen_where",),
       elastic=("zeek.intel.seen.where",), security_onion=("intel.seen_where",), plain=("seen.where",)),
    _f("intel.seen_node", "seen.node", "text", malcolm=("zeek.intel.seen_node",), elastic=("zeek.intel.seen.node",),
       security_onion=("intel.seen_node",), plain=("seen.node",)),
    _f("intel.matched", "matched", "names", elastic=("zeek.intel.matched",), security_onion=("intel.matched",),
       plain=("matched",)),
    # Malcolm merges the sources with CIF's into threat.indicator.provider: not read
    _f("intel.sources", "sources", "names", elastic=("zeek.intel.sources",), security_onion=("intel.sources",),
       plain=("sources",)),
    _f("file.fuid", "fuid", "text1", malcolm=("zeek.fuid",), elastic=("zeek.intel.fuid",),
       security_onion=("log.id.fuid",), plain=("fuid",)),
), doc="base/frameworks/intel/main.zeek", key=("zeek.uid",), sequence=("intel.indicator",))

# ---- application transactions with no family of their own: app_tx ----------------------------------------------

FTP = _log("ftp", "app_tx", (
    *_endpoints("ftp"),
    # Zeek writes "<unknown>" until a USER command is seen
    _f("user.name", "user", "text1", malcolm=("related.user",), elastic=("zeek.ftp.user", "user.name"),
       security_onion=("ftp.user",), plain=("user",)),
    _f("app.command", "command", "text", malcolm=("zeek.ftp.command",), elastic=("zeek.ftp.command",),
       security_onion=("ftp.command",), plain=("command",)),
    # the argument of a PASS command is a password (or Zeek's "<hidden>"): zeek.py never types it
    _f("app.arg", "arg", "text", malcolm=("zeek.ftp.arg",), elastic=("zeek.ftp.arg",),
       security_onion=("ftp.argument",), plain=("arg",)),
    _f("app.reply_code", "reply_code", "count", malcolm=("zeek.ftp.reply_code",), elastic=("zeek.ftp.reply.code",),
       security_onion=("server.reply_code",), plain=("reply_code",)),
    _f("app.reply", "reply_msg", "text", malcolm=("zeek.ftp.reply_msg",), elastic=("zeek.ftp.reply.msg",),
       security_onion=("server.reply_message",), plain=("reply_msg",)),
    _f("file.mime_type", "mime_type", "text", malcolm=("zeek.ftp.mime_type",), elastic=("file.mime_type",),
       security_onion=("file.mimetype",), plain=("mime_type",)),
    _f("file.size", "file_size", "count", malcolm=("zeek.ftp.file_size",), elastic=("file.size",),
       security_onion=("file.size",), plain=("file_size",)),
    _f("ftp.data_channel.passive", "data_channel.passive", "flag", malcolm=("zeek.ftp.data_channel.passive",),
       elastic=("zeek.ftp.data_channel.passive",), security_onion=("ftp.data_channel_passive",),
       plain=("data_channel.passive",)),
    _f("ftp.data_channel.orig_h", "data_channel.orig_h", "ip", malcolm=("zeek.ftp.data_channel.orig_h",),
       elastic=("zeek.ftp.data_channel.originating_host",), security_onion=("ftp.data_channel_source.ip",),
       plain=("data_channel.orig_h",)),
    _f("ftp.data_channel.resp_h", "data_channel.resp_h", "ip", malcolm=("zeek.ftp.data_channel.resp_h",),
       elastic=("zeek.ftp.data_channel.response_host",), security_onion=("ftp.data_channel_destination.ip",),
       plain=("data_channel.resp_h",)),
    _f("ftp.data_channel.resp_p", "data_channel.resp_p", "port", malcolm=("zeek.ftp.data_channel.resp_p",),
       elastic=("zeek.ftp.data_channel.response_port",), security_onion=("ftp.data_channel_destination.port",),
       plain=("data_channel.resp_p",)),
    _f("file.fuid", "fuid", "text1", malcolm=("zeek.fuid",), elastic=("zeek.ftp.file.uid",),
       security_onion=("fuid",), plain=("fuid",)),
), doc="base/protocols/ftp/info.zeek", transport="tcp", key=("zeek.uid",),
    secrets={MALCOLM: MALCOLM_SECRETS, ELASTIC: ("zeek.ftp.password",), SECURITY_ONION: ("ftp.password",),
             PLAIN: ("password",)})

SMTP = _log("smtp", "app_tx", (
    *_endpoints("smtp"),
    _f("app.trans_depth", "trans_depth", "count", malcolm=("zeek.smtp.trans_depth",),
       elastic=("zeek.smtp.transaction_depth",), security_onion=("smtp.transaction_depth",),
       plain=("trans_depth",)),
    *(_f(f"smtp.{typed}", native, kind, malcolm=(f"zeek.smtp.{native}",), elastic=(f"zeek.smtp.{elastic}",),
         security_onion=(f"smtp.{so}",), plain=(native,))
      for typed, native, kind, elastic, so in (
          ("helo", "helo", "text", "helo", "helo"), ("mail_from", "mailfrom", "text", "mail_from", "mail_from"),
          ("rcpt_to", "rcptto", "names", "rcpt_to", "recipient_to"), ("from", "from", "text", "from", "from"),
          ("to", "to", "names", "to", "to"), ("cc", "cc", "names", "cc", "cc"),
          ("reply_to", "reply_to", "text", "reply_to", "reply_to"), ("msg_id", "msg_id", "text", "msg_id",
                                                                      "message_id"),
          ("subject", "subject", "text", "subject", "subject"),
          ("x_originating_ip", "x_originating_ip", "ip", "x_originating_ip", "x_originating_ip"),
          ("path", "path", "addresses", "path", "path"), ("user_agent", "user_agent", "text", "user_agent",
                                                          "useragent"),
          ("tls", "tls", "flag", "tls", "tls"))),
    _f("app.reply", "last_reply", "text", malcolm=("zeek.smtp.last_reply",), elastic=("zeek.smtp.last_reply",),
       security_onion=("smtp.last_reply",), plain=("last_reply",)),
    # Malcolm renames fuids to fuid and lifts it (a list)
    _f("file.fuids", "fuids", "list", malcolm=("zeek.fuid",), elastic=("zeek.smtp.fuids",),
       security_onion=("log.id.fuids",), plain=("fuids",)),
), doc="base/protocols/smtp/main.zeek", transport="tcp", key=("zeek.uid",), sequence=("app.trans_depth",))

IRC = _log("irc", "app_tx", (
    *_endpoints("irc"),
    _f("irc.nick", "nick", "text", malcolm=("zeek.irc.nick",), elastic=("zeek.irc.nick",),
       security_onion=("irc.nickname",), plain=("nick",)),
    _f("user.name", "user", "text1", malcolm=("related.user",), elastic=("user.name",),
       security_onion=("irc.username",), plain=("user",)),
    _f("app.command", "command", "text", malcolm=("zeek.irc.command",), elastic=("zeek.irc.command",),
       security_onion=("irc.command.type",), plain=("command",)),
    _f("app.arg", "value", "text", malcolm=("zeek.irc.value",), elastic=("zeek.irc.value",),
       security_onion=("irc.command.value",), plain=("value",)),
    # Zeek writes a JOIN's channel key here: zeek.py never types it
    _f("irc.addl", "addl", "text", malcolm=("zeek.irc.addl",), elastic=("zeek.irc.addl",),
       security_onion=("irc.command.info",), plain=("addl",)),
    _f("file.name", "dcc_file_name", "text", malcolm=("zeek.irc.dcc_file_name",), elastic=("file.name",),
       security_onion=("file.name",), plain=("dcc_file_name",)),
    _f("file.size", "dcc_file_size", "count", malcolm=("zeek.irc.dcc_file_size",),
       elastic=("zeek.irc.dcc_file_size",), security_onion=("file.size",), plain=("dcc_file_size",)),
    _f("file.mime_type", "dcc_mime_type", "text", malcolm=("zeek.irc.dcc_mime_type",), elastic=("file.mime_type",),
       security_onion=("file.mime_type",), plain=("dcc_mime_type",)),
    _f("file.fuid", "fuid", "text1", malcolm=("zeek.fuid",), elastic=("zeek.irc.fuid",),
       security_onion=("log.id.fuid",), plain=("fuid",)),
), doc="base/protocols/irc/main.zeek", transport="tcp", key=("zeek.uid",))

MYSQL = _log("mysql", "app_tx", (
    *_endpoints("mysql"),
    _f("app.command", "cmd", "text", malcolm=("zeek.mysql.cmd",), elastic=("zeek.mysql.cmd",),
       security_onion=("mysql.command",), plain=("cmd",)),
    _f("app.arg", "arg", "text", malcolm=("zeek.mysql.arg",), elastic=("zeek.mysql.arg",),
       security_onion=("mysql.argument",), plain=("arg",)),
    _f("app.success", "success", "flag", malcolm=("zeek.mysql.success",), elastic=("zeek.mysql.success",),
       security_onion=("mysql.success",), plain=("success",)),
    # Malcolm removes a rows value of 0
    _f("app.rows", "rows", "count", malcolm=("zeek.mysql.rows",), elastic=("zeek.mysql.rows",),
       security_onion=("mysql.rows",), plain=("rows",)),
    _f("app.reply", "response", "text", malcolm=("zeek.mysql.response",), elastic=("zeek.mysql.response",),
       security_onion=("mysql.response",), plain=("response",)),
), doc="base/protocols/mysql/main.zeek", transport="tcp", key=("zeek.uid",))

_NO_ELASTIC = {ELASTIC: "elastic/integrations packages/zeek has no data stream for this log"}
_NO_SO = {SECURITY_ONION: "Security Onion 2.4 has no ingest pipeline for this log"}

# Microsoft SQL Server's TDS: a Zeek package (amzn/zeek-plugin-tds) that Malcolm and Security Onion ship
TDS = _log("tds", "app_tx", (
    *_endpoints("tds", absent=(ELASTIC,)),
    _f("app.command", "command", "text", malcolm=("zeek.tds.command",), security_onion=("tds.command",),
       plain=("command",)),
), absent=_NO_ELASTIC, doc="https://github.com/amzn/zeek-plugin-tds", transport="tcp", key=("zeek.uid",))

POSTGRESQL = _log("postgresql", "app_tx", (
    *_endpoints("postgresql", absent=(ELASTIC, SECURITY_ONION)),
    _f("user.name", "user", "text1", malcolm=("related.user",), plain=("user",)),
    _f("postgresql.database", "database", "text", malcolm=("zeek.postgresql.database",), plain=("database",)),
    _f("postgresql.application_name", "application_name", "text", malcolm=("zeek.postgresql.application_name",),
       plain=("application_name",)),
    _f("app.command", "frontend", "text", malcolm=("zeek.postgresql.frontend",), plain=("frontend",)),
    _f("app.arg", "frontend_arg", "text", malcolm=("zeek.postgresql.frontend_arg",), plain=("frontend_arg",)),
    _f("app.reply", "backend", "text", malcolm=("zeek.postgresql.backend",), plain=("backend",)),
    _f("postgresql.backend_arg", "backend_arg", "text", malcolm=("zeek.postgresql.backend_arg",),
       plain=("backend_arg",)),
    # Malcolm moves success into event.result whenever it sets one, and removes a rows value of 0
    _f("app.success", "success", "flag", malcolm=("zeek.postgresql.success",), plain=("success",)),
    _f("app.rows", "rows", "count", malcolm=("zeek.postgresql.rows",), plain=("rows",)),
), absent={**_NO_ELASTIC, **_NO_SO}, doc="base/protocols/postgresql/main.zeek", transport="tcp", key=("zeek.uid",))

REDIS = _log("redis", "app_tx", (
    *_endpoints("redis", absent=(ELASTIC, SECURITY_ONION)),
    _f("app.command", "cmd.name", "text", malcolm=("zeek.redis.cmd_name",), plain=("cmd.name",)),
    # the key of an AUTH or HELLO command may be a credential: zeek.py never types it. The command's value
    # (cmd.value) is application data and is not read.
    _f("app.arg", "cmd.key", "text", malcolm=("zeek.redis.cmd_key",), plain=("cmd.key",)),
    _f("app.success", "success", "flag", malcolm=("zeek.redis.success",), plain=("success",)),
    _f("app.reply", "reply.value", "text", malcolm=("zeek.redis.reply",), plain=("reply.value",)),
), absent={**_NO_ELASTIC, **_NO_SO}, doc="base/protocols/redis/main.zeek", transport="tcp", key=("zeek.uid",))

SOCKS = _log("socks", "app_tx", (
    *_endpoints("socks"),
    _f("socks.version", "version", "count", malcolm=("zeek.socks.version",), elastic=("zeek.socks.version",),
       security_onion=("socks.version",), plain=("version",)),
    _f("user.name", "user", "text1", malcolm=("related.user",), elastic=("zeek.socks.user", "user.name"),
       security_onion=("socks.user",), plain=("user",)),
    _f("app.reply", "status", "text", malcolm=("zeek.socks.server_status",), elastic=("zeek.socks.status",),
       security_onion=("socks.status",), plain=("status",)),
    # Elastic renames request.name to request.host, and Security Onion renames request_host and bound_name, names
    # Zeek does not write: where the request's address and name land in those shapes is unverified
    _f("socks.request.host", "request.host", "ip", malcolm=("zeek.socks.request_host",),
       elastic=("zeek.socks.request.host",), plain=("request.host",)),
    _f("socks.request.name", "request.name", "text", malcolm=("zeek.socks.request_name",),
       security_onion=("socks.request.name",), plain=("request.name",)),
    _f("socks.request.port", "request_p", "port", malcolm=("zeek.socks.request_p", "zeek.socks.request_port"),
       elastic=("zeek.socks.request.port",), security_onion=("socks.request.port",), plain=("request_p",)),
    _f("socks.bound.host", "bound.host", "ip", malcolm=("zeek.socks.bound_host",),
       elastic=("zeek.socks.bound.host",), security_onion=("socks.bound.host",), plain=("bound.host",)),
    _f("socks.bound.name", "bound.name", "text", malcolm=("zeek.socks.bound_name",),
       elastic=("zeek.socks.bound.name",), plain=("bound.name",)),
    _f("socks.bound.port", "bound_p", "port", malcolm=("zeek.socks.bound_p", "zeek.socks.bound_port"),
       elastic=("zeek.socks.bound.port",), security_onion=("socks.bound.port",), plain=("bound_p",)),
), doc="base/protocols/socks/main.zeek", transport="tcp", key=("zeek.uid",),
    secrets={MALCOLM: MALCOLM_SECRETS, ELASTIC: ("zeek.socks.password",), SECURITY_ONION: ("socks.password",),
             PLAIN: ("password",)})

TUNNEL = _log("tunnel", "app_tx", (
    *_endpoints("tunnel"),
    # Malcolm removes the "Tunnel::" prefix of both values; zeek.py removes it in every shape
    _f("tunnel.type", "tunnel_type", "text", malcolm=("zeek.tunnel.tunnel_type",), elastic=("zeek.tunnel.type",),
       security_onion=("tunnel.type",), plain=("tunnel_type",)),
    _f("app.command", "action", "text", malcolm=("zeek.tunnel.action",), elastic=("zeek.tunnel.action",),
       security_onion=("event.action",), plain=("action",)),
), doc="base/frameworks/tunnels/main.zeek", key=("zeek.uid",))

SIP = _log("sip", "app_tx", (
    *_endpoints("sip"),
    _f("app.trans_depth", "trans_depth", "count", malcolm=("zeek.sip.trans_depth",),
       elastic=("zeek.sip.transaction_depth",), security_onion=("sip.transaction.depth",), plain=("trans_depth",)),
    _f("app.command", "method", "text", malcolm=("zeek.sip.method",), elastic=("zeek.sip.sequence.method",),
       security_onion=("sip.method",), plain=("method",)),
    _f("app.arg", "uri", "text", malcolm=("zeek.sip.uri",), elastic=("zeek.sip.uri",), security_onion=("sip.uri",),
       plain=("uri",)),
    _f("app.reply_code", "status_code", "count", malcolm=("zeek.sip.status_code",), elastic=("zeek.sip.status.code",),
       security_onion=("server.status_code",), plain=("status_code",)),
    _f("app.reply", "status_msg", "text", malcolm=("zeek.sip.status_msg",), elastic=("zeek.sip.status.msg",),
       security_onion=("server.status_message",), plain=("status_msg",)),
    _f("sip.user_agent", "user_agent", "text", malcolm=("zeek.sip.user_agent",), elastic=("zeek.sip.user_agent",),
       security_onion=("client.user_agent",), plain=("user_agent",)),
    _f("sip.call_id", "call_id", "text", malcolm=("zeek.sip.call_id",), elastic=("zeek.sip.call_id",),
       security_onion=("sip.call_id",), plain=("call_id",)),
    _f("sip.request_from", "request_from", "text", malcolm=("zeek.sip.request_from",),
       elastic=("zeek.sip.request.from",), security_onion=("sip.request.from",), plain=("request_from",)),
    _f("sip.request_to", "request_to", "text", malcolm=("zeek.sip.request_to",), elastic=("zeek.sip.request.to",),
       security_onion=("sip.request.to",), plain=("request_to",)),
), doc="base/protocols/sip/main.zeek", key=("zeek.uid",), sequence=("app.trans_depth",))

SNMP = _log("snmp", "app_tx", (
    *_endpoints("snmp"),
    _f("snmp.duration_s", "duration", "seconds", malcolm=("zeek.snmp.duration",), elastic=("zeek.snmp.duration",),
       security_onion=("event.duration",), plain=("duration",)),
    _f("snmp.version", "version", "text", malcolm=("zeek.snmp.version",), elastic=("zeek.snmp.version",),
       security_onion=("snmp.version",), plain=("version",)),
    *(_f(f"snmp.{name}", name, "count", malcolm=(f"zeek.snmp.{name}",), elastic=(f"zeek.snmp.{elastic}",),
         security_onion=(f"snmp.{elastic}",), plain=(name,))
      for name, elastic in (("get_requests", "get.requests"), ("get_bulk_requests", "get.bulk_requests"),
                            ("get_responses", "get.responses"), ("set_requests", "set.requests"))),
    _f("snmp.display_string", "display_string", "text", malcolm=("zeek.snmp.display_string",),
       elastic=("zeek.snmp.display_string",), security_onion=("snmp.display_string",), plain=("display_string",)),
    _f("snmp.up_since", "up_since", "time", malcolm=("zeek.snmp.up_since",), elastic=("zeek.snmp.up_since",),
       security_onion=("snmp.up_since",), plain=("up_since",)),
), doc="base/protocols/snmp/main.zeek", transport="udp", key=("zeek.uid",),
    # SNMPv1 and v2c communities are shared secrets sent in cleartext (SNMPv3 writes its user name there instead)
    secrets={MALCOLM: ("zeek.snmp.community",), ELASTIC: ("zeek.snmp.community",),
             SECURITY_ONION: ("snmp.community",), PLAIN: ("community",)})

RADIUS = _log("radius", "app_tx", (
    *_endpoints("radius"),
    _f("user.name", "username", "text1", malcolm=("related.user",), elastic=("zeek.radius.username", "user.name"),
       security_onion=("user.name",), plain=("username",)),
    _f("radius.mac", "mac", "mac", malcolm=("zeek.radius.mac",), elastic=("zeek.radius.mac",),
       security_onion=("host.mac",), plain=("mac",)),
    _f("radius.framed_addr", "framed_addr", "ip", malcolm=("zeek.radius.framed_addr",),
       elastic=("zeek.radius.framed_addr",), security_onion=("radius.framed_address",), plain=("framed_addr",)),
    _f("radius.tunnel_client", "tunnel_client", "text", malcolm=("zeek.radius.tunnel_client",),
       elastic=("zeek.radius.tunnel_client",), plain=("tunnel_client",)),
    _f("radius.connect_info", "connect_info", "text", malcolm=("zeek.radius.connect_info",),
       elastic=("zeek.radius.connect_info",), security_onion=("radius.connect_info",), plain=("connect_info",)),
    _f("app.reply", "reply_msg", "text", malcolm=("zeek.radius.reply_msg",), elastic=("zeek.radius.reply_msg",),
       security_onion=("radius.reply_message",), plain=("reply_msg",)),
    _f("app.result", "result", "text", malcolm=("zeek.radius.result",), elastic=("zeek.radius.result",),
       security_onion=("radius.result",), plain=("result",)),
    _f("radius.ttl_s", "ttl", "seconds", malcolm=("zeek.radius.ttl",), elastic=("zeek.radius.ttl",),
       plain=("ttl",)),
), doc="base/protocols/radius/main.zeek", transport="udp", key=("zeek.uid",))

ANALYZER_LOGS: tuple[ZeekLog, ...] = (DNS, HTTP, SSL, X509, FILES, PE, SSH, NOTICE, WEIRD, SIGNATURES, INTEL, FTP, SMTP,
                                      IRC, MYSQL, TDS, POSTGRESQL, REDIS, SOCKS, TUNNEL, SIP, SNMP, RADIUS)
ZEEK_LOGS: tuple[ZeekLog, ...] = (CONN, *ANALYZER_LOGS)
_BY_NAME: dict[tuple[str, str], ZeekLog] = {(shape, name): log for log in ZEEK_LOGS
                                            for shape, names in log.names.items() for name in names}


def lookup_log(shape: str, name: object) -> ZeekLog | None:
    """The catalogued log a shipper's log name denotes in one shape, or None when it is not catalogued."""
    if not isinstance(name, str):
        return None
    return _BY_NAME.get((shape, name.strip().lower()))
