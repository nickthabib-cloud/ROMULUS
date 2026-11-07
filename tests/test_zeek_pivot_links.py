"""Zeek rows in the investigator's pivots, the network-flow link and the external-destination baseline.

- The flow link keys a Zeek ICMP connection by its addresses and transport (its ports are ICMP type and counterpart
  values, stored outside the port fields by Elastic), matches every spelling of ICMP a shipper stores (Zeek writes
  "icmp" for ICMPv6, typed "ipv6-icmp"), and searches plain Zeek JSON by Zeek's own literal dotted field names.
- An entity timeline over a target whose inventory names a Zeek log by its dispatch token selects that log's rows in
  every layout the target can be searched by, and counts the token as planned, not unresolved.
- A target with no Zeek field keeps the intents it always had.
"""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from romulus.agent.models import EntityRef
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest, IdsAlertsArgs, IdsAlertsRequest
from romulus.baseline.spec import SPEC_BY_ID, KeyContext
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek import normalize_plain_zeek
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
from romulus.hunt.pivot import (
    SURICATA_TIMELINE_DATASETS,
    PivotExecutor,
    _prefilter_raw,
    zeek_source_groups,
)
from romulus.sources.profile import contract_from_types
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl

T0 = datetime(2024, 11, 18, 13, 55, tzinfo=UTC)
T1 = T0 + timedelta(minutes=20)

ELASTIC_TYPES = {"@timestamp": "date", "event.dataset": "keyword", "data_stream.dataset": "keyword",
                 "source.ip": "ip", "destination.ip": "ip", "source.port": "long", "destination.port": "long",
                 "network.transport": "keyword", "network.community_id": "keyword",
                 "zeek.connection.icmp.type": "long", "zeek.connection.icmp.code": "long",
                 "zeek.session_id": "keyword"}
MALCOLM_TYPES = {"@timestamp": "date", "event.dataset": "keyword", "event.provider": "keyword",
                 "source.ip": "ip", "destination.ip": "ip", "source.port": "long", "destination.port": "long",
                 "network.transport": "keyword", "network.community_id": "keyword", "zeek.uid": "keyword"}
PLAIN_TYPES = {"@timestamp": "date", "_path": "keyword", "uid": "keyword", "id.orig_h": "ip", "id.orig_p": "long",
               "id.resp_h": "ip", "id.resp_p": "long", "proto": "keyword"}
SURICATA_TYPES = {"@timestamp": "date", "event.dataset": "keyword", "source.ip": "ip", "destination.ip": "ip",
                  "source.port": "long", "destination.port": "long", "network.transport": "keyword"}


class Pivot:
    """The executor's planning over given contracts; fetching returns the given events the link retains."""

    def __init__(self, contracts, events=(), inventory=None):
        self.contracts = contracts
        self.events = list(events)
        self.dataset_inventory = inventory or {}
        self.calls = []

    def _intents(self, request):
        return PivotExecutor._intents(self, request)

    def plan(self, request):
        return PivotExecutor.plan(self, request)

    def _unsearchable_ip_coverage(self, request, intents=None):
        return PivotExecutor._unsearchable_ip_coverage(self, request, intents)

    def fetch_intents(self, owner, fetch_key, intents, retain, *, anchor_ts=None, query_cap=None,
                      planning_coverage=None, persist=True):
        from romulus.hunt.pivot import PivotEventBatch
        self.calls.append(intents)
        return PivotEventBatch(status="complete", task_ids=["t"], events=[e for e in self.events if retain(e)],
                               raw_sources={}, coverage=list(planning_coverage or []), reasons=[], duration_ms=1)

    def save_batch_selection(self, batch, events):
        del batch, events


def zeek(hit, plain_log=None):
    if plain_log is not None:
        event = normalize_plain_zeek(hit, plain_log, sensor="sensor-plain")
    else:
        [event] = normalize_hits([hit])[0]
    event.fields.pop("network.community_id", None)          # keyed by the 5-tuple
    return event


def link(pivot, anchor_event):
    request = LinkAnchor(finding_id="f-1", ts=anchor_event.ts, host=anchor_event.host,
                         event_ids=[anchor_event.id], events=[anchor_event])
    linked = LinkFetcher(pivot, T0, T1).fetch(request, "network_flow", LinkWindow(label="w", start=T0, end=T1))
    return linked, [intent for intents in pivot.calls for intent in intents]


def groups(intent):
    return [[(p.field, p.op, tuple(p.value) if isinstance(p.value, list) else p.value) for p in group]
            for group in intent.any_of]


def test_an_elastic_zeek_icmp_flow_is_found_by_addresses_and_matched_by_its_typed_tuple():
    anchor = zeek(zf.malcolm(zf.ICMP_ECHO, "anchor"))
    other = zeek(zf.elastic(zf.ICMP_ECHO, "elastic-copy", sensor="sensor-zeek-02"))
    stray = zeek(zf.elastic(replace(zf.ICMP_ECHO, uid="Cother", orig_p=3, resp_p=1), "other-type"))
    assert other.get("source.port") == 8 and other.get("network.transport") == "icmp"
    pivot = Pivot({"zeek-el": contract_from_types("zeek-el", ELASTIC_TYPES, role="network")}, [anchor, other, stray])
    linked, [intent] = link(pivot, anchor)
    assert groups(intent) == [
        [("source.ip", "eq", "10.0.0.5"), ("destination.ip", "eq", "203.0.113.10")],
        [("source.ip", "eq", "203.0.113.10"), ("destination.ip", "eq", "10.0.0.5")],
    ]
    assert [(p.field, p.op, p.value) for p in intent.filters] == [
        ("network.transport", "in", ["icmp", "ipv6-icmp", "icmpv6"])]
    assert other.id in linked.event_ids and stray.id not in linked.event_ids


def test_a_zeek_icmpv6_flow_matches_the_icmp_zeek_stores():
    anchor = zeek(zf.malcolm(zf.ICMP6_ECHO, "v6-anchor"))
    other = zeek(zf.security_onion(zf.ICMP6_ECHO, "v6-so", sensor="sensor-zeek-02"))
    assert anchor.get("network.transport") == other.get("network.transport") == "ipv6-icmp"
    pivot = Pivot({"malcolm": contract_from_types("malcolm", MALCOLM_TYPES, role="network")}, [anchor, other])
    linked, [intent] = link(pivot, anchor)
    assert "icmp" in next(p for p in intent.filters if p.field == "network.transport").value
    assert other.id in linked.event_ids


def test_plain_zeek_json_is_searched_by_zeek_s_own_dotted_names():
    conn = replace(zf.Conn(), service=None)
    anchor = zeek(zf.malcolm(conn, "tcp-anchor"))
    other = zeek(zf.plain(conn, "pl-1"), plain_log="conn")
    pivot = Pivot({"plain": contract_from_types("plain", PLAIN_TYPES, role="network")}, [anchor, other])
    linked, [intent] = link(pivot, anchor)
    assert groups(intent)[0] == [("id.orig_h", "eq", "10.0.0.5"), ("id.orig_p", "eq", 51000),
                                 ("id.resp_h", "eq", "203.0.113.10"), ("id.resp_p", "eq", 443)]
    assert [(p.field, p.value) for p in intent.filters] == [("proto", "tcp")]
    assert other.id in linked.event_ids


def test_a_target_without_the_flow_fields_is_not_searched():
    anchor = zeek(zf.malcolm(zf.Conn(), "a"))
    pivot = Pivot({"bare": contract_from_types("bare", {"@timestamp": "date", "proto": "keyword"},
                                               role="network")})
    _linked, intents = link(pivot, anchor)
    assert intents == []


def timeline(ip="10.0.0.5"):
    return EntityTimelineRequest(tool="entity_timeline", arguments=EntityTimelineArgs(
        entity=EntityRef(kind="ip", value=ip), start=T0, end=T1))


def test_a_zeek_token_in_the_inventory_selects_the_log_s_rows_in_every_searchable_layout():
    contract = contract_from_types("net", {**MALCOLM_TYPES, "event.module": "keyword"}, role="network")
    pivot = Pivot({"net": contract}, inventory={"net": ("suricata.eve.flow", "zeek:dns")})
    intents, unresolved = PivotExecutor.plan(pivot, timeline())
    by_purpose = {intent.purpose: intent for intent in intents}
    assert set(by_purpose) == {"agent:entity_timeline:suricata.eve.flow", "agent:entity_timeline:zeek:dns"}
    token = by_purpose["agent:entity_timeline:zeek:dns"]
    selectors = {tuple(g[:-1]) for g in groups(token)}
    assert selectors == {
        (("event.dataset", "in", ("zeek.dns",)),),
        (("event.provider", "eq", "zeek"), ("event.dataset", "in", ("dns",))),
        (("event.module", "eq", "zeek"), ("event.dataset", "in", ("dns",))),
    }
    assert {g[-1][0] for g in groups(token)} == {"source.ip", "destination.ip"}
    assert unresolved == []


def test_a_zeek_capable_target_without_an_inventory_also_reads_zeek_rows():
    contract = contract_from_types("net", MALCOLM_TYPES, role="network")
    [intent] = PivotExecutor._intents(Pivot({"net": contract}), timeline())
    dataset_groups = {tuple(g[:-1]) for g in groups(intent)}
    assert (("event.provider", "eq", "zeek"), ("event.dataset", "in", tuple(_malcolm_names()))) in dataset_groups


def _malcolm_names():
    from romulus.evidence.zeek_catalog import MALCOLM, ZEEK_LOGS
    return sorted({name for log in ZEEK_LOGS for name in log.names.get(MALCOLM, ())})


def test_a_target_with_no_zeek_field_keeps_its_intents():
    contract = contract_from_types("eve", SURICATA_TYPES, role="network")
    [intent] = PivotExecutor._intents(Pivot({"eve": contract}), timeline())
    assert [(p.field, p.op, p.value) for p in intent.filters] == [
        ("event.dataset", "in", SURICATA_TIMELINE_DATASETS)]
    assert groups(intent) == [[("source.ip", "eq", "10.0.0.5")], [("destination.ip", "eq", "10.0.0.5")]]
    alerts = IdsAlertsRequest(tool="ids_alerts", arguments=IdsAlertsArgs(
        entity=EntityRef(kind="ip", value="10.0.0.5"), start=T0, end=T1))
    [intent] = PivotExecutor._intents(Pivot({"eve": contract}), alerts)
    assert [(p.field, p.value) for p in intent.filters] == [("event.dataset", "suricata.eve.alert")]


def test_ids_alerts_read_zeek_alert_logs_on_a_zeek_capable_target():
    contract = contract_from_types("net", MALCOLM_TYPES, role="network")
    alerts = IdsAlertsRequest(tool="ids_alerts", arguments=IdsAlertsArgs(
        entity=EntityRef(kind="ip", value="10.0.0.5"), start=T0, end=T1))
    [intent] = PivotExecutor._intents(Pivot({"net": contract}), alerts)
    selectors = {tuple(g[:-1]) for g in groups(intent)}
    assert (("event.dataset", "eq", "suricata.eve.alert"),) in selectors
    assert (("event.provider", "eq", "zeek"), ("event.dataset", "in",
                                               ("intel", "notice", "signatures", "weird"))) in selectors


def test_zeek_source_groups_are_empty_where_nothing_can_be_searched():
    contract = contract_from_types("net", {"@timestamp": "date", "source.ip": "ip"}, role="network")
    assert zeek_source_groups(contract) == []


def test_the_raw_family_prefilter_keeps_only_zeek_rows_of_the_requested_family():
    dns = zl.malcolm(zl.ROWS["dns"], "dns-1")
    conn = zf.malcolm(zf.Conn(), "conn-1")
    unread = zf.malcolm(zf.Conn(), "opcua-1")
    unread["_source"]["event"]["dataset"] = "opcua_binary"
    ics = zf.malcolm(zf.Conn(), "modbus-1")
    ics["_source"]["event"]["dataset"] = "modbus"
    kept = _prefilter_raw([dns, conn, ics, unread], {"dns_query"})
    assert [hit["_id"] for hit in kept] == ["dns-1", "opcua-1"]
    [event] = normalize_hits(kept[:1])[0]
    assert event.family == "dns_query"


def test_external_destinations_read_zeek_conn_dns_and_ssl():
    spec = SPEC_BY_ID["bl.ext_dest"]
    assert {"zeek:conn", "zeek:dns", "zeek:ssl"} <= set(spec.datasets)
    [event] = normalize_hits([zf.malcolm(zf.Conn(resp_h="198.51.100.10"), "ext-1")])[0]
    keys = spec.keys(event, KeyContext(is_internal=lambda address: str(address).startswith("10.")))
    assert {key.key["kind"] for key in keys} >= {"dest_ip", "dest_network"}
    assert all(key.dedup_token for key in keys)          # the connection counts once
