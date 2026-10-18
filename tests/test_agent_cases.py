"""Agent domain contracts: safe entities, strict tools, and deterministic seed clustering."""
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from romulus.agent.cases import cluster_seed_candidates
from romulus.agent.models import AgentDecision, EntityRef
from romulus.agent.tools import parse_tool_request, tool_catalog
from romulus.evidence.typed import RawRef, TypedEvent, fv

T = datetime(2024, 11, 18, 14, 29, 59, tzinfo=UTC)


def _candidate(cid: str, ts: datetime, entities: list[list[str]], lane: str = "lead", priority: float = 30.0):
    return {"id": cid, "ts": ts, "entities": entities, "lane": lane, "priority": priority}


def test_network_sensor_host_is_an_observer_not_an_affected_host():
    event = TypedEvent(
        id="e1", family="net_alert", ts=T, host="inetfw",
        fields={"source.ip": fv("198.51.100.4", "raw:src_ip"),
                "destination.ip": fv("10.0.0.8", "raw:dest_ip")},
        raw=[RawRef(target="network", native_id="1")], normalizer="test@1",
    )

    assert ("host", "inetfw", "observer") in event.entities()
    assert ("host", "inetfw", "host") not in event.entities()


def test_network_seed_uses_destination_ip_before_source_and_ignores_observer():
    candidate = _candidate("c1", T, [["host", "inetfw", "observer"],
                                      ["ip", "198.51.100.4", "src"],
                                      ["ip", "10.0.0.8", "dst"]])

    clusters = cluster_seed_candidates([candidate])

    assert len(clusters) == 1
    assert clusters[0].primary_entity == EntityRef(kind="ip", value="10.0.0.8", role="dst")
    assert clusters[0].seed_candidate_ids == ["c1"]


def test_same_entity_joins_by_gap_across_fixed_bucket_boundary():
    candidates = [
        _candidate("c1", T, [["host", "video", "host"]]),
        _candidate("c2", T + timedelta(seconds=2), [["host", "video", "host"]], priority=40),
        _candidate("c3", T + timedelta(minutes=16), [["host", "video", "host"]]),
    ]

    clusters = cluster_seed_candidates(candidates, gap=timedelta(minutes=15))

    assert [c.seed_candidate_ids for c in clusters] == [["c1", "c2"], ["c3"]]
    assert clusters[0].priority == 40


def test_tool_arguments_forbid_raw_dsl_and_unknown_fields():
    decision = AgentDecision(
        action="pivot", tool="entity_timeline",
        arguments={"entity": {"kind": "ip", "value": "198.51.100.4", "role": "src"},
                   "start": T, "end": T + timedelta(minutes=5),
                   "query": {"bool": {"must": []}}},
        hypothesis="attacker authenticated", expected_true="auth event", expected_false="no auth event",
        reasoning="Follow the observed source IP.",
    )

    with pytest.raises(ValidationError, match="query"):
        parse_tool_request(decision)


def test_auth_activity_schema_accepts_only_account_or_host_entities():
    decision = AgentDecision(
        action="pivot", tool="auth_activity",
        arguments={"entity": {"kind": "ip", "value": "198.51.100.4", "role": "src"},
                   "start": T, "end": T + timedelta(minutes=5)},
        hypothesis="account activity", expected_true="auth event", expected_false="no auth event",
        reasoning="Check authentication.",
    )

    with pytest.raises(ValidationError, match="entity"):
        parse_tool_request(decision)


def test_ids_alerts_schema_and_catalog_accept_only_ip_entities():
    decision = AgentDecision(
        action="pivot", tool="ids_alerts",
        arguments={"entity": {"kind": "host", "value": "inetfw", "role": "observer"},
                   "start": T, "end": T + timedelta(minutes=5)},
        hypothesis="host alerts", expected_true="IDS alert", expected_false="no IDS alert",
        reasoning="Check the named sensor.",
    )

    with pytest.raises(ValidationError, match="IP"):
        parse_tool_request(decision)
    assert tool_catalog()["ids_alerts"] == {
        "arguments": "entity {kind: ip, value, role}, start, end",
        "purpose": "retrieve IDS alerts for a known IP",
    }
