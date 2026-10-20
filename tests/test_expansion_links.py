"""Typed deterministic link fetchers used by post-sweep expansion."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.models import PivotCoverage, PivotTimeRange
from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.context import EntryPointPromotion
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow, usable_key
from romulus.hunt.pivot import PivotEventBatch
from romulus.sources.profile import contract_from_types

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
T1 = T0 + timedelta(minutes=10)
IP = "203.0.113.8"


def event(event_id, family, *, ts=T0, host="web1", **fields):
    return TypedEvent(
        id=event_id, family=family, ts=ts, host=host,
        fields={name.replace("__", "."): fv(value, f"{event_id}:{name}")
                for name, value in fields.items()},
        raw=[RawRef(target="host-x", native_id=event_id, digest="d")], normalizer="test@1",
    )


def window():
    return LinkWindow(label="anchor +10 min", start=T0, end=T1)


def coverage(status="complete"):
    unresolved = [] if status == "complete" else [PivotTimeRange(
        start=T0.isoformat(), end=T1.isoformat(), reason="cap:2<total:3",
    )]
    return [PivotCoverage(
        target="host-x", dataset="linux.audit", start=T0, end=T1, status=status,
        reasons=[] if status == "complete" else ["cap:2<total:3"], returned=2,
        total=3 if status != "complete" else 2, unresolved_ranges=unresolved,
    )]


class FakePivot:
    def __init__(self, events, status="complete"):
        self.events = events
        self.status = status
        self.calls = []
        self.contracts = {
            "host-x": contract_from_types("host-x", {
                "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
                "source.ip": "ip", "destination.ip": "ip", "user.name": "keyword",
                "process.auid": "keyword",
            }),
            "arkime_sessions3-x": contract_from_types("arkime_sessions3-x", {
                "firstPacket": "date", "lastPacket": "date", "network.community_id": "keyword",
                "source.ip": "ip", "destination.ip": "ip", "source.port": "integer",
                "destination.port": "integer",
            }),
        }

    def _intents(self, request):
        from romulus.hunt.pivot import PivotExecutor
        return PivotExecutor._intents(self, request)

    def fetch_intents(self, owner, fetch_key, intents, retain, *, anchor_ts=None, query_cap=None):
        self.calls.append((owner, fetch_key, intents, anchor_ts, query_cap))
        selected = [item for item in self.events if retain(item)]
        return PivotEventBatch(
            status=self.status, task_ids=["task-1"], events=selected, raw_sources={},
            coverage=coverage(self.status), reasons=[] if self.status == "complete" else ["cap:2<total:3"],
            duration_ms=1,
        )


def cases(matched=True):
    lineage_anchor = event("lineage-a", "process_exec", process__executable="/bin/sh",
                           process__pid=100, process__ppid=1,
                           process__session_id=42, process__auid="1000")
    lineage_other = event("lineage-b", "process_exec", ts=T0 + timedelta(seconds=1),
                          process__executable="/usr/bin/id",
                          process__pid=101, process__ppid=100 if matched else 999,
                          process__session_id=42, process__auid="1000")

    session_anchor = event("session-a", "process_exec", process__pid=200, process__ppid=1,
                           process__session_id=42, process__auid="1000")
    session_other = event("session-b", "net_socket", ts=T0 + timedelta(seconds=1),
                          process__pid=200, process__session_id=42 if matched else 43,
                          process__auid="1000", destination__ip=IP, destination__port=443)

    flow_anchor = event("flow-a", "net_flow", network__community_id="1:abc",
                        source__ip="10.0.0.2", source__port=50000,
                        destination__ip=IP, destination__port=443, network__transport="tcp")
    flow_other = event("flow-b", "net_session", ts=T0 + timedelta(seconds=1), host="sensor",
                       network__community_id="1:abc" if matched else "1:other",
                       source__ip="10.0.0.2", source__port=50000,
                       destination__ip=IP, destination__port=443, network__transport="tcp")
    flow_socket = event(
        "flow-socket", "net_socket", ts=T0 + timedelta(seconds=1),
        destination__ip=IP if matched else "198.51.100.2", destination__port=443,
        network__transport="tcp", process__pid=210,
    )

    ip_anchor = event("ip-a", "http_access", source__ip=IP)
    ip_other = event("ip-b", "auth", ts=T0 + timedelta(seconds=1), host="other",
                     source__ip=IP if matched else "198.51.100.2", user__name="root")

    account_anchor = event("account-a", "process_exec", process__auid="1000", process__pid=300)
    account_other = event("account-b", "process_exec", ts=T0 + timedelta(seconds=1), host="other",
                          process__auid="1000" if matched else "1001", process__pid=301)

    host_anchor = event("host-a", "process_exec", process__pid=400)
    host_other = event("host-b", "process_exec", ts=T0 + timedelta(seconds=1),
                       host="web1" if matched else "other", process__pid=401)

    return {
        "process_lineage": (lineage_anchor, lineage_other),
        "login_session": (session_anchor, session_other),
        "network_flow": (flow_anchor, flow_other),
        "flow_host_side": (flow_anchor, flow_socket),
        "source_ip": (ip_anchor, ip_other),
        "account": (account_anchor, account_other),
        "host_after_anchor": (host_anchor, host_other),
    }


def anchor(kind, anchor_event):
    return LinkAnchor(
        finding_id=f"finding-{kind}", ts=anchor_event.ts, host=anchor_event.host,
        event_ids=[anchor_event.id], events=[anchor_event],
    )


@pytest.mark.parametrize("value", [
    None, "", "  ", 4294967295, -1, "4294967295", "-1", "(null)", "(none)", "unset",
    "0.0.0.0", "::", "127.0.0.1", "::1",
])
def test_usable_key_rejects_sentinels_and_non_routable_ips(value):
    assert not usable_key(value)


@pytest.mark.parametrize("link_type", ["login_session", "process_lineage", "host_after_anchor"])
def test_host_bound_observed_links_refuse_missing_host(link_type):
    anchor_event, _linked = cases()[link_type]
    pivot = FakePivot([])
    request = LinkAnchor(
        finding_id=f"finding-{link_type}", ts=anchor_event.ts, host=None,
        event_ids=[anchor_event.id], events=[anchor_event.model_copy(update={"host": None})],
    )

    result = LinkFetcher(pivot, T0, T1).fetch(request, link_type, window())

    assert result.status == "unsupported"
    assert not pivot.calls


def test_inferred_account_link_refuses_unpushable_key_instead_of_full_scan():
    anchor_event = event("account-a", "process_exec", user__name="root")
    pivot = FakePivot([])
    # This host contract deliberately has no user.name/process.auid predicate.
    pivot.contracts = {
        "host-x": contract_from_types("host-x", {
            "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
        }),
    }

    result = LinkFetcher(pivot, T0, T1).fetch(
        anchor("account", anchor_event), "account", window(),
    )

    assert result.status == "unsupported"
    assert result.reasons == ["key not pushable; full-dataset scan refused"]
    assert not pivot.calls


def test_inferred_source_ip_link_refuses_unfiltered_host_dataset_scan():
    anchor_event = event("ip-a", "http_access", source__ip=IP)
    pivot = FakePivot([])
    pivot.contracts = {
        "host-x": contract_from_types("host-x", {
            "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
        }),
    }

    result = LinkFetcher(pivot, T0, T1).fetch(
        anchor("source_ip", anchor_event), "source_ip", window(),
    )

    assert result.status == "unsupported"
    assert result.reasons == ["key not pushable; full-dataset scan refused"]
    assert not pivot.calls


@pytest.mark.parametrize("link_type", sorted(cases()))
def test_each_link_fetcher_returns_only_typed_matches(link_type):
    anchor_event, linked = cases(matched=True)[link_type]
    pivot = FakePivot([anchor_event, linked])

    result = LinkFetcher(pivot, T0, T1).fetch(anchor(link_type, anchor_event), link_type, window())

    assert result.status == "complete"
    assert linked.id in result.event_ids
    assert result.key
    assert result.strength == ("inferred" if link_type in {
        "source_ip", "account", "host_after_anchor", "flow_host_side",
    } else "observed")
    if link_type == "network_flow":
        assert "host_side" not in result.key


@pytest.mark.parametrize("link_type", sorted(cases()))
def test_each_link_fetcher_rejects_a_typed_key_mismatch(link_type):
    anchor_event, unrelated = cases(matched=False)[link_type]
    pivot = FakePivot([anchor_event, unrelated])

    result = LinkFetcher(pivot, T0, T1).fetch(anchor(link_type, anchor_event), link_type, window())

    assert result.status == "complete"
    assert unrelated.id not in result.event_ids


@pytest.mark.parametrize("link_type", sorted(cases()))
def test_each_link_fetcher_preserves_capped_partial_coverage(link_type):
    anchor_event, linked = cases(matched=True)[link_type]
    pivot = FakePivot([anchor_event, linked], status="partial")

    result = LinkFetcher(pivot, T0, T1).fetch(anchor(link_type, anchor_event), link_type, window())

    assert result.status == "partial"
    assert result.coverage[0].unresolved_ranges
    assert "cap:2<total:3" in result.reasons


def test_link_key_runs_at_most_once_per_fetcher():
    anchor_event, linked = cases()["login_session"]
    pivot = FakePivot([anchor_event, linked])
    fetcher = LinkFetcher(pivot, T0, T1)
    request = anchor("login_session", anchor_event)

    first = fetcher.fetch(request, "login_session", window())
    second = fetcher.fetch(request, "login_session", window())

    assert first == second
    assert len(pivot.calls) == 1


def test_process_lineage_uses_latest_pid_identity_at_or_before_child_time():
    root = event("root-old", "process_exec", process__executable="/bin/sh",
                 process__pid=100, process__ppid=1,
                 process__session_id=42)
    child = event("child-old", "process_exec", ts=T0 + timedelta(seconds=1),
                  process__executable="/usr/bin/id",
                  process__pid=101, process__ppid=100, process__session_id=42)
    reused = event("root-reused", "process_exec", ts=T0 + timedelta(seconds=2),
                   process__executable="/usr/bin/cron",
                   process__pid=100, process__ppid=1, process__session_id=99)
    wrong_child = event("child-new", "process_exec", ts=T0 + timedelta(seconds=3),
                        process__executable="/usr/bin/true",
                        process__pid=102, process__ppid=100, process__session_id=99)
    pivot = FakePivot([root, child, reused, wrong_child])

    result = LinkFetcher(pivot, T0, T1).fetch(
        anchor("process_lineage", root), "process_lineage", window(),
    )

    assert child.id in result.event_ids
    assert wrong_child.id not in result.event_ids


def test_login_session_never_crosses_session_ids_even_when_auid_matches():
    root = event("root", "process_exec", process__pid=100, process__session_id=42, process__auid="1000")
    other = event("other", "process_exec", ts=T0 + timedelta(seconds=1),
                  process__pid=101, process__session_id=43, process__auid="1000")

    result = LinkFetcher(FakePivot([root, other]), T0, T1).fetch(
        anchor("login_session", root), "login_session", window(),
    )

    assert other.id not in result.event_ids


def test_normalized_audit_login_reaches_session_link_and_entry_promotion():
    raw = (
        'type=USER_LOGIN msg=audit(1731950250.400:76807): pid=900 uid=0 auid=1001 '
        'ses=42 acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.8 res=success'
    )
    hit = {
        "_id": "audit-login", "_index": "host-x",
        "_source": {
            "@timestamp": "2024-11-18T14:00:50+00:00", "host": {"name": "web1"},
            "event": {"dataset": "linux.audit", "original": raw},
        },
    }
    [login], skips, errors = normalize_hits([hit])
    assert skips == {} and errors == []
    root = event(
        "root", "process_exec", process__pid=100, process__session_id=42, process__auid="1001",
    )
    anchor_request = anchor("login_session", root)

    linked = LinkFetcher(FakePivot([login]), T0, T1).fetch(
        anchor_request, "login_session", window(),
    )
    context_anchor = ContextAnchor(
        id="F-anchor", anchor_class="credential_access", lane="urgent",
        claim="credential access followed the login", events=[root],
    )
    context_link = ContextLink(
        id=linked.id, link_type=linked.link_type, strength=linked.strength,
        key=linked.key, evidence_events=[root, login], status=linked.status,
    )

    matches = EntryPointPromotion().consume_linked(context_anchor, context_link, [login])

    assert linked.event_ids == [login.id]
    assert len(matches) == 1
    assert matches[0].proposed_lane == "high"


def test_network_flow_exact_tuple_queries_both_directions():
    root = event(
        "flow-no-community", "net_flow", source__ip="10.0.0.2", source__port=50000,
        destination__ip=IP, destination__port=443, network__transport="tcp",
    )
    pivot = FakePivot([root])

    LinkFetcher(pivot, T0, T1).fetch(anchor("network_flow", root), "network_flow", window())

    network_intent = next(
        intent for _owner, _key, intents, _ts, _cap in pivot.calls for intent in intents
        if intent.target == "arkime_sessions3-x"
    )
    assert [[(predicate.field, predicate.value) for predicate in group]
            for group in network_intent.any_of] == [
        [("source.ip", "10.0.0.2"), ("source.port", 50000),
         ("destination.ip", IP), ("destination.port", 443)],
        [("source.ip", IP), ("source.port", 443),
         ("destination.ip", "10.0.0.2"), ("destination.port", 50000)],
    ]


def test_host_socket_endpoint_match_is_inferred_not_observed_network_flow():
    flow = event(
        "flow", "net_flow", host="sensor", network__community_id="1:abc",
        source__ip="10.0.0.2", source__port=50000,
        destination__ip=IP, destination__port=443, network__transport="tcp",
    )
    unrelated_process = event(
        "socket", "net_socket", host="web1", ts=T0 + timedelta(minutes=2),
        destination__ip=IP, destination__port=443, network__transport="tcp",
        process__pid=900,
    )
    pivot = FakePivot([flow, unrelated_process])
    request = LinkAnchor(
        finding_id="finding-flow", ts=flow.ts, host="web1",
        event_ids=[flow.id], events=[flow],
    )

    observed = LinkFetcher(pivot, T0, T1).fetch(request, "network_flow", window())
    inferred = LinkFetcher(pivot, T0, T1).fetch(request, "flow_host_side", window())

    assert unrelated_process.id not in observed.event_ids
    assert observed.strength == "observed"
    assert inferred.event_ids == [unrelated_process.id]
    assert inferred.strength == "inferred"
