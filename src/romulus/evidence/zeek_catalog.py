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
  policy sets ``event.module`` to "zeek" (salt/elasticfleet/files/integrations-dynamic/grid-nodes_general/
  zeek-logs.json) and its ingest pipeline ``zeek.conn`` (salt/elasticsearch/files/ingest/zeek.conn, commit
  c29f11863e96b86540fae76386c5e5ec3b8fe7d4) sets ``event.dataset`` to the bare "conn" and renames: ``duration`` to
  ``event.duration`` (seconds, unconverted), ``orig_bytes``/``resp_bytes`` to ``client.bytes``/``server.bytes``,
  ``orig_ip_bytes``/``resp_ip_bytes`` to ``client.ip_bytes``/``server.ip_bytes``, ``orig_pkts``/``resp_pkts`` to
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
"""

from __future__ import annotations

from dataclasses import dataclass, field

MALCOLM, ELASTIC, SECURITY_ONION, PLAIN = "malcolm", "elastic", "security_onion", "plain"
SHAPES = (MALCOLM, ELASTIC, SECURITY_ONION, PLAIN)
SHAPE_NAMES = {MALCOLM: "Malcolm", ELASTIC: "Elastic", SECURITY_ONION: "Security Onion", PLAIN: "plain Zeek JSON"}

# Readers (zeek.py) for each kind of value. Zeek's types: addr, port, count, interval, string, bool, set[string].
KINDS = frozenset({"ip", "port", "count", "seconds", "text", "flag", "services", "names", "mac"})


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
# time of the record's first packet (Zeek's `ts`).
SENSOR_PATHS = _each(malcolm=("node",), elastic=("agent.name", "host.name"),
                     security_onion=("observer.name",))
TIME_PATHS = _each(malcolm=("@timestamp", "firstPacket:ms"), elastic=("@timestamp",),
                   security_onion=("@timestamp",), plain=("ts",))

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

ZEEK_LOGS: tuple[ZeekLog, ...] = (CONN,)
_BY_NAME: dict[tuple[str, str], ZeekLog] = {(shape, name): log for log in ZEEK_LOGS
                                            for shape, names in log.names.items() for name in names}


def lookup_log(shape: str, name: object) -> ZeekLog | None:
    """The catalogued log a shipper's log name denotes in one shape, or None when it is not catalogued."""
    if not isinstance(name, str):
        return None
    return _BY_NAME.get((shape, name.strip().lower()))
