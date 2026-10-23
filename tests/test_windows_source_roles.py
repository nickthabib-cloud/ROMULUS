"""Typed source roles and OS-aware dataset/key selection replace target-name assumptions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from romulus.agent.models import EntityRef
from romulus.agent.tools import EntityTimelineArgs, EntityTimelineRequest, ProcessTreeArgs, ProcessTreeRequest
from romulus.config import Settings
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.windows_catalog import (
    EVENT_CLASSES,
    SECURITY,
    SYSMON,
    SYSMON_CHANNEL,
    WINDOWS_DATASET_FAMILIES,
    WINDOWS_HOST_DATASETS,
)
from romulus.hunt import run as hunt_run
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow, _portable_windows_account
from romulus.hunt.manifest import build_manifest
from romulus.hunt.pivot import PivotExecutor, _is_network
from romulus.hunt.sweep import LINUX_HOST_DATASETS, Sweep
from romulus.sources import profile as profile_module
from romulus.sources.compile import build_query
from romulus.sources.models import Predicate, SearchIntent, Window
from romulus.sources.profile import build_profile, contract_from_types, flatten_mapping

START = datetime(2026, 1, 2, tzinfo=UTC)
END = START + timedelta(hours=1)


def _windows_types() -> dict[str, str]:
    return {
        "@timestamp": "date",
        "event.dataset": "keyword",
        "winlog.computer_name": "keyword",
        "winlog.channel": "keyword",
        "winlog.provider_name": "keyword",
        "winlog.event_id": "keyword",
        "winlog.event_data": "flattened",
    }


def _event(event_id: int, *, channel=SYSMON_CHANNEL, provider=SYSMON, data=None):
    return normalize_hits(
        [
            {
                "_index": "logs-windows",
                "_id": f"w-{event_id}",
                "_source": {
                    "@timestamp": "2026-01-02T00:05:00Z",
                    "agent": {"type": "winlogbeat"},
                    "event": {"dataset": "windows.sysmon_operational"},
                    "winlog": {
                        "channel": channel,
                        "provider_name": provider,
                        "event_id": event_id,
                        "computer_name": "WS01.example.test",
                        "record_id": 100 + event_id,
                        "event_data": data or {},
                    },
                },
            }
        ]
    )[0][0]


def test_contract_role_is_typed_and_never_inferred_from_a_misleading_target_name():
    host = contract_from_types("definitely-network-by-name", {"@timestamp": "date"}, role="host")
    network = contract_from_types("definitely-host-by-name", {"@timestamp": "date"}, role="network")

    assert host.role == "host" and _is_network(host.target, host) is False
    assert network.role == "network" and _is_network(network.target, network) is True


def test_sweep_filters_derive_from_role_and_os_not_the_index_name():
    linux = contract_from_types("network-looking", {"@timestamp": "date", "event.dataset": "keyword"}, role="host")
    windows = contract_from_types("anything", _windows_types(), role="host")
    network = contract_from_types("host-looking", {"@timestamp": "date", "event.dataset": "keyword"}, role="network")
    sweep = object.__new__(Sweep)
    sweep.stats = {}

    assert Sweep._filters_for(sweep, linux.target, linux)[0].value == list(LINUX_HOST_DATASETS)
    assert Sweep._filters_for(sweep, windows.target, windows) == []
    selectors = Sweep._any_of_for(sweep, windows.target, windows)
    assert {group[0].field for group in selectors} == {"event.dataset", "event.channel"}
    assert next(group[0].value for group in selectors if group[0].field == "event.dataset") == list(
        WINDOWS_HOST_DATASETS
    )
    assert Sweep._filters_for(sweep, network.target, network) == []


def test_flattened_fields_and_explicit_native_to_typed_aliases_compile():
    mapping = {"idx": {"mappings": {"properties": {"winlog": {"properties": {
        "computer_name": {"type": "keyword"},
        "event_data": {"type": "flattened"},
    }}}}}}
    flattened = flatten_mapping(mapping)
    contract = contract_from_types("idx", {"@timestamp": "date", "event.dataset": "keyword", **flattened})

    assert flattened["winlog.event_data"] == "flattened"
    assert contract.spec("host.name").native == "winlog.computer_name"
    assert contract.spec("process.command_line").native == "winlog.event_data.CommandLine"
    assert contract.spec("process.command_line").type == "flattened"
    query = build_query(
        SearchIntent(
            kind="raw",
            target="idx",
            window=Window(start=START, end=END),
            filters=[Predicate(field="process.command_line", op="eq", value="whoami.exe")],
        ),
        contract,
    )
    assert {"term": {"winlog.event_data.CommandLine": "whoami.exe"}} in query["bool"]["filter"]


def test_windows_alias_predicates_query_every_native_representation():
    contract = contract_from_types("idx", _windows_types(), role="host")

    pid_query = build_query(SearchIntent(
        kind="raw", target="idx", window=Window(start=START, end=END),
        filters=[Predicate(field="process.pid", op="eq", value=512)],
    ), contract)
    source_query = build_query(SearchIntent(
        kind="raw", target="idx", window=Window(start=START, end=END),
        filters=[Predicate(field="source.ip", op="eq", value="192.0.2.1")],
    ), contract)

    assert {next(iter(clause["term"])) for clause in pid_query["bool"]["filter"][1]["bool"]["should"]} == {
        "winlog.event_data.ProcessId", "winlog.event_data.NewProcessId",
    }
    assert {next(iter(clause["term"])) for clause in source_query["bool"]["filter"][1]["bool"]["should"]} == {
        "winlog.event_data.SourceIp", "winlog.event_data.IpAddress",
    }


def test_short_windows_host_predicate_is_a_case_insensitive_fqdn_superset():
    contract = contract_from_types("idx", _windows_types(), role="host")
    query = build_query(SearchIntent(
        kind="raw", target="idx", window=Window(start=START, end=END),
        filters=[Predicate(field="host.name", op="eq", value="ws01")],
    ), contract)

    host_filter = query["bool"]["filter"][1]
    patterns = [next(iter(item["wildcard"].values()))["value"] for item in host_filter["bool"]["should"]]
    assert patterns == ["ws01", "ws01.*"]
    assert all(next(iter(item["wildcard"].values()))["case_insensitive"] for item in host_filter["bool"]["should"])


def test_fqdn_windows_host_predicate_also_retrieves_native_short_names():
    contract = contract_from_types("idx", _windows_types(), role="host")
    query = build_query(SearchIntent(
        kind="raw", target="idx", window=Window(start=START, end=END),
        filters=[Predicate(field="host.name", op="eq", value="WS01.Example.Test.")],
    ), contract)

    host_filter = query["bool"]["filter"][1]
    patterns = [next(iter(item["wildcard"].values()))["value"] for item in host_filter["bool"]["should"]]
    assert patterns == ["WS01", "WS01.*"]


def test_windows_host_retention_treats_short_and_fqdn_names_as_the_same_host():
    event = _event(1, data={"ProcessId": "512"})
    request = ProcessTreeRequest(
        tool="process_tree",
        arguments=ProcessTreeArgs(host="WS01.Example.Test", process_id=512, start=START, end=END),
    )

    assert PivotExecutor._retain(request, event)


def test_security_4688_parent_pid_alias_includes_native_process_id():
    contract = contract_from_types("idx", _windows_types(), role="host")
    query = build_query(SearchIntent(
        kind="raw", target="idx", window=Window(start=START, end=END),
        filters=[Predicate(field="process.ppid", op="eq", value=512)],
    ), contract)

    natives = {next(iter(clause["term"])) for clause in query["bool"]["filter"][1]["bool"]["should"]}
    assert "winlog.event_data.ProcessId" in natives


def test_data_stream_dataset_is_an_explicit_typed_alias():
    types = _windows_types()
    types.pop("event.dataset")
    types["data_stream.dataset"] = "constant_keyword"
    contract = contract_from_types("idx", types, role="host")

    query = build_query(SearchIntent(
        kind="raw", target="idx", window=Window(start=START, end=END),
        filters=[Predicate(field="event.dataset", op="in", value=["system.security"])],
    ), contract)

    assert query["bool"]["filter"][1] == {"terms": {"data_stream.dataset": ["system.security"]}}


def test_forwarded_events_are_retrieved_and_mapped_to_every_w0_windows_family():
    assert "windows.forwarded" in WINDOWS_HOST_DATASETS
    assert WINDOWS_DATASET_FAMILIES["windows.forwarded"] == frozenset(
        event.family for event in EVENT_CLASSES
    )


def test_live_profile_records_the_typed_role_and_profiles_the_event_computer():
    class Client:
        version = "8.0"

        class settings:
            es_flavor = "elasticsearch"

        @staticmethod
        def mapping(_target):
            return {"idx": {"mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {"dataset": {"type": "keyword"}}},
                "winlog": {"properties": {
                    "computer_name": {"type": "keyword"},
                    "event_data": {"type": "flattened"},
                }},
            }}}}

        @staticmethod
        def search(_target, body):
            source = body["aggs"]["hosts"]["composite"]["sources"][0]
            assert source == {"host": {"terms": {"field": "winlog.computer_name"}}}
            return {
                "hits": {"total": {"value": 1}},
                "aggregations": {
                    "tmin": {},
                    "tmax": {},
                    "ds": {"buckets": [{"key": "windows.security", "doc_count": 1}]},
                    "hosts": {"buckets": [{"key": {"host": "ws01.example.test"}, "doc_count": 1}]},
                },
            }

    profile, contract = build_profile(Client(), "name-does-not-matter")

    assert profile.role == "host" and contract.role == "host"
    assert contract.os_family == "windows"
    assert profile.hosts == {"ws01.example.test": 1}


def test_manifest_records_profile_role_and_os_family():
    manifest = build_manifest(
        Settings(), Window(start=START, end=END), {}, "broad", ["mixed"],
        {"mixed": {
            "id": "profile-1", "backend_version": "8.0", "doc_count": 4,
            "datasets": {"windows.security": 4}, "role": "host", "os_family": "windows",
        }},
    )

    assert manifest["source_profiles"]["mixed"] == {
        "id": "profile-1", "backend_version": "8.0", "doc_count": 4,
        "datasets": {"windows.security": 4}, "role": "host", "os_family": "windows",
    }


def test_resume_contract_preflight_refuses_role_or_os_change(monkeypatch):
    class Profile:
        id = "profile-2"
        role = "network"

    contract = contract_from_types("mixed", {"@timestamp": "date"}, role="network", os_family="unknown")
    monkeypatch.setattr(hunt_run, "build_profile", lambda _client, _target: (Profile(), contract))

    with pytest.raises(RuntimeError, match="source role/OS changed"):
        hunt_run._contracts(
            Settings(), object(), {
                "id": "h1",
                "_resume_scope_check": True,
                "manifest": {"targets": ["mixed"], "source_profiles": {
                    "mixed": {"id": "profile-1", "role": "host", "os_family": "windows"},
                }},
            }, object(),
        )


def test_live_profile_pages_a_5000_host_windows_inventory():
    class Client:
        version = "8.0"

        class settings:
            es_flavor = "elasticsearch"

        calls = 0

        @staticmethod
        def mapping(_target):
            return {"idx": {"mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {"dataset": {"type": "keyword"}}},
                "winlog": {"properties": {"computer_name": {"type": "keyword"}}},
            }}}}

        @classmethod
        def search(cls, _target, body):
            cls.calls += 1
            composite = body["aggs"]["hosts"]["composite"]
            start = int((composite.get("after") or {"host": "ws-1"})["host"][2:]) + 1
            stop = min(start + composite["size"], 5_000)
            buckets = [
                {"key": {"host": f"ws{number:04d}"}, "doc_count": 1}
                for number in range(start, stop)
            ]
            hosts = {"buckets": buckets}
            if stop < 5_000:
                hosts["after_key"] = {"host": f"ws{stop - 1:04d}"}
            return {
                "hits": {"total": {"value": 5_000}},
                "aggregations": {
                    "tmin": {}, "tmax": {},
                    "ds": {"buckets": [{"key": "windows.security", "doc_count": 5_000}]},
                    "hosts": hosts,
                },
            }

    profile, contract = build_profile(Client(), "windows-5000")

    assert len(profile.hosts) == 5_000
    assert Client.calls == 10
    assert contract.host_inventory_complete is True
    assert profile.notes == []


def test_live_profile_marks_host_inventory_partial_at_page_budget(monkeypatch):
    monkeypatch.setattr(profile_module, "HOST_INVENTORY_PAGE_LIMIT", 1)

    class Client:
        version = "8.0"

        class settings:
            es_flavor = "elasticsearch"

        @staticmethod
        def mapping(_target):
            return {"idx": {"mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {"dataset": {"type": "keyword"}}},
                "winlog": {"properties": {"computer_name": {"type": "keyword"}}},
            }}}}

        @staticmethod
        def search(_target, _body):
            return {
                "hits": {"total": {"value": 501}},
                "aggregations": {
                    "tmin": {}, "tmax": {}, "ds": {"buckets": []},
                    "hosts": {
                        "buckets": [
                            {"key": {"host": f"ws{number:04d}"}, "doc_count": 1}
                            for number in range(500)
                        ],
                        "after_key": {"host": "ws0499"},
                    },
                },
            }

    profile, contract = build_profile(Client(), "windows-truncated")

    assert len(profile.hosts) == 500
    assert profile.notes == ["hosts inventory truncated (composite page budget 1 exceeded)"]
    assert contract.host_inventory_complete is False


def test_windows_host_timeline_and_process_tree_use_catalog_datasets_and_native_host_key():
    contract = contract_from_types("not-host", _windows_types(), role="host")
    executor = PivotExecutor(None, None, "h1", {contract.target: contract})
    timeline = EntityTimelineRequest(
        tool="entity_timeline",
        arguments=EntityTimelineArgs(
            entity=EntityRef(kind="host", value="ws01", role="host"), start=START, end=END
        ),
    )
    process = ProcessTreeRequest(
        tool="process_tree",
        arguments=ProcessTreeArgs(host="ws01", process_id=512, start=START, end=END),
    )

    [timeline_intent] = executor._intents(timeline)
    process_intents = executor._intents(process)
    assert any(group[0].field == "event.channel" for group in timeline_intent.any_of)
    assert next(item.value for item in timeline_intent.filters if item.field == "host.name") == "ws01"
    assert len(process_intents) == 1
    process_datasets = next(
        group[0].value for group in process_intents[0].any_of if group[0].field == "event.dataset"
    )
    assert {"system.security", "windows.security", "windows.sysmon_operational", "system.system",
            "windows.system", "windows.forwarded"} <= set(process_datasets)


def test_winlogbeat_without_event_dataset_is_retrieved_by_sweep_timeline_and_links():
    """Winlogbeat 7/8 mappings expose winlog.channel even when event.dataset is absent.

    https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html
    """
    types = _windows_types()
    types.pop("event.dataset")
    contract = contract_from_types("winlogbeat-8", types, role="host", os_family="windows")
    sweep = object.__new__(Sweep)
    sweep.stats = {}
    sweep_groups = Sweep._any_of_for(sweep, contract.target, contract)
    executor = PivotExecutor(None, None, "h1", {contract.target: contract})
    timeline = EntityTimelineRequest(
        tool="entity_timeline",
        arguments=EntityTimelineArgs(
            entity=EntityRef(kind="host", value="ws01", role="host"), start=START, end=END,
        ),
    )
    [timeline_intent] = executor._intents(timeline)
    process = _event(1, data={"ProcessId": "512"})
    fetcher = LinkFetcher(executor, START, END)
    planned = fetcher._lineage(
        LinkAnchor(finding_id="a", ts=process.ts, host=process.host, events=[process]),
        LinkWindow(label="near", start=START, end=END),
    )[2]

    assert [[predicate.field for predicate in group] for group in sweep_groups] == [["event.channel"]]
    assert any(group[0].field == "event.channel" for group in timeline_intent.any_of)
    assert planned and all(any(group[0].field == "event.channel" for group in intent.any_of) for intent in planned)
    for intent in [timeline_intent, *planned]:
        query = build_query(intent, contract)
        assert "winlog.channel" in str(query["bool"]["should"])


def test_windows_lineage_session_and_flow_host_links_select_os_specific_keys_and_datasets():
    contract = contract_from_types(
        "misleading-network-name",
        {
            **_windows_types(),
            "winlog.event_data.ProcessGuid": "keyword",
            "winlog.event_data.TargetLogonId": "keyword",
            "winlog.event_data.DestinationIp": "ip",
            "winlog.event_data.DestinationPort": "integer",
        },
        role="host",
    )
    executor = PivotExecutor(None, None, "h1", {contract.target: contract})
    fetcher = LinkFetcher(executor, START, END)
    process = _event(
        1,
        data={
            "ProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "ParentProcessGuid": "{11111111-2222-3333-4444-555555555555}",
            "ProcessId": "512",
        },
    )
    auth = _event(
        4624,
        channel="Security",
        provider=SECURITY,
        data={"TargetLogonId": "0x44"},
    )
    net = _event(
        3,
        data={
            "SourceIp": "192.0.2.10",
            "SourcePort": "50100",
            "DestinationIp": "198.51.100.10",
            "DestinationPort": "443",
            "Protocol": "tcp",
        },
    )
    window = LinkWindow(label="near", start=START, end=END)

    lineage = fetcher._lineage(LinkAnchor(finding_id="a", ts=process.ts, host=process.host, events=[process]), window)
    session = fetcher._session(LinkAnchor(finding_id="b", ts=auth.ts, host=auth.host, events=[auth]), window)
    flow = fetcher._flow_host_side(LinkAnchor(finding_id="c", ts=net.ts, host=net.host, events=[net]), window)

    assert lineage[0]["process.guid"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert session[0]["auth.session_key"] == "ws01:0x44"
    for planned in (lineage[2], session[2], flow[2]):
        assert planned
        assert all("linux.audit" not in str(intent.model_dump(mode="json")) for intent in planned)


def test_windows_account_links_use_the_canonical_sid_or_domain_name_identity():
    contract = contract_from_types("windows", _windows_types(), role="host")
    executor = PivotExecutor(None, None, "h1", {contract.target: contract})
    fetcher = LinkFetcher(executor, START, END)
    process = _event(1, data={"ProcessId": "512", "User": r"EXAMPLE\Alice"})

    planned = fetcher._account(
        LinkAnchor(finding_id="account", ts=process.ts, host=process.host, events=[process]),
        LinkWindow(label="after", start=START, end=END),
    )

    assert planned[0]["user.entity_id"] == r"name:example\alice"
    assert planned[2]
    assert all(intent.filters[0].value == r"name:example\alice" for intent in planned[2])
    assert all(build_query(intent, contract)["bool"]["filter"] for intent in planned[2])


def test_windows_process_tree_honors_pid_fences_and_reports_when_they_are_missing():
    root = _event(1, data={"ProcessId": "512"}).model_copy(update={"id": "root", "ts": START + timedelta(minutes=10)})
    child = _event(1, data={"ProcessId": "600", "ParentProcessId": "512"}).model_copy(
        update={"id": "child", "ts": START + timedelta(minutes=15)}
    )
    terminated = _event(5, data={"ProcessId": "512"}).model_copy(
        update={"id": "terminated", "ts": START + timedelta(minutes=20)}
    )
    reused = _event(1, data={"ProcessId": "700", "ParentProcessId": "512"}).model_copy(
        update={"id": "reused", "ts": START + timedelta(minutes=30)}
    )
    args = ProcessTreeArgs(host="ws01", process_id=512, start=START, end=END)

    selected, reason = PivotExecutor._select_windows_process_tree(
        [root, child, terminated, reused], args, root.ts, termination_attested=True,
    )
    unfenced, missing = PivotExecutor._select_windows_process_tree(
        [root, child, reused], args, root.ts, termination_attested=False,
    )

    assert {event.id for event in selected} == {"root", "child"}
    assert reason is None
    assert {event.id for event in unfenced} == {"root", "child", "reused"}
    assert missing == "process_tree PID fence evidence unavailable"


def test_windows_process_tree_root_is_latest_at_or_before_anchor_not_later_pid_reuse():
    prior = _event(1, data={
        "ProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", "ProcessId": "512",
    }).model_copy(update={"id": "prior", "ts": START + timedelta(minutes=10)})
    prior_child = _event(1, data={
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ParentProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
        "ProcessId": "600", "ParentProcessId": "512",
    }).model_copy(update={"id": "prior-child", "ts": START + timedelta(minutes=15)})
    later_reuse = _event(1, data={
        "ProcessGuid": "{BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}", "ProcessId": "512",
    }).model_copy(update={"id": "later-reuse", "ts": START + timedelta(minutes=21)})
    later_child = _event(1, data={
        "ProcessGuid": "{22222222-3333-4444-5555-666666666666}",
        "ParentProcessGuid": "{BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}",
        "ProcessId": "700", "ParentProcessId": "512",
    }).model_copy(update={"id": "later-child", "ts": START + timedelta(minutes=22)})
    args = ProcessTreeArgs(host="ws01", process_id=512, start=START, end=END)

    selected, reason = PivotExecutor._select_windows_process_tree(
        [prior, prior_child, later_reuse, later_child], args, START + timedelta(minutes=20),
    )

    assert {event.id for event in selected} == {"prior", "prior-child"}
    assert reason is None


def test_pid_fallback_link_is_inferred_until_4689_collection_is_attested():
    class Facts:
        def __init__(self, attested):
            self.attested = attested

        def attests(self, _host, fact, **arguments):
            return (
                self.attested and fact == "audit_policy"
                and arguments == {"subcategory": "Process Termination", "outcome": "success"}
            )

    process = _event(4688, channel="Security", provider=SECURITY, data={"NewProcessId": "0x200"})
    contract = contract_from_types("windows", _windows_types(), role="host")
    window = LinkWindow(label="near", start=START, end=END)

    def strength(attested):
        executor = PivotExecutor(
            None, None, "h1", {contract.target: contract}, site_facts=Facts(attested),
        )
        return LinkFetcher(executor, START, END)._lineage(
            LinkAnchor(finding_id="lineage", ts=process.ts, host=process.host, events=[process]), window,
        )[1]

    assert strength(False) == "inferred"
    assert strength(True) == "observed"


def test_windows_session_link_is_bounded_by_boot_fences():
    before = _event(4624, channel="Security", provider=SECURITY, data={
        "TargetLogonId": "0x44", "TargetUserSid": "S-1-5-21-1-2-3-1001",
    }).model_copy(update={"id": "before", "ts": START + timedelta(minutes=10)})
    same_boot = before.model_copy(update={"id": "same-boot", "ts": START + timedelta(minutes=15)})
    boot = _event(6005, channel="System", provider="EventLog").model_copy(
        update={"id": "boot", "ts": START + timedelta(minutes=20)}
    )
    after = before.model_copy(update={"id": "after", "ts": START + timedelta(minutes=25)})
    contract = contract_from_types("windows", _windows_types(), role="host")
    fetcher = LinkFetcher(PivotExecutor(None, None, "h1", {contract.target: contract}), START, END)

    planned = fetcher._session(
        LinkAnchor(finding_id="session", ts=before.ts, host=before.host, events=[before]),
        LinkWindow(label="near", start=START, end=END),
    )
    selected = planned[4]([same_boot, boot, after])

    assert {event.id for event in selected} == {"before", "same-boot"}


def test_windows_logon_account_link_prefers_target_and_refuses_generic_sid():
    logon = _event(4624, channel="Security", provider=SECURITY, data={
        "SubjectUserSid": "S-1-5-18", "SubjectUserName": "SYSTEM",
        "TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetUserName": "alice",
        "TargetDomainName": "EXAMPLE", "TargetLogonId": "0x44",
    })
    generic = logon.model_copy(update={
        "id": "generic",
        "fields": {**logon.fields, "auth.target_account": logon.fields["user.entity_id"]},
    })
    contract = contract_from_types("windows", _windows_types(), role="host")
    fetcher = LinkFetcher(PivotExecutor(None, None, "h1", {contract.target: contract}), START, END)
    window = LinkWindow(label="after", start=START, end=END)

    target_plan = fetcher._account(LinkAnchor(
        finding_id="target", ts=logon.ts, host=logon.host, events=[logon],
    ), window)
    generic_plan = fetcher._account(LinkAnchor(
        finding_id="generic", ts=generic.ts, host=generic.host, events=[generic],
    ), window)

    assert target_plan[0] == {"auth.target_account": "sid:s-1-5-21-1-2-3-1001", "actor": "inferred"}
    assert generic_plan[2] == []
    assert generic_plan[5] == "cross-host account identity is well-known or machine-generic"


def test_placeholder_account_key_is_never_portable_across_hosts():
    assert _portable_windows_account("name:-") is False


def test_windows_process_tree_prefers_process_guid_lineage_over_pid_reuse():
    root = _event(1, data={
        "ProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", "ProcessId": "512",
    }).model_copy(update={"id": "root", "ts": START + timedelta(minutes=10)})
    child = _event(1, data={
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ParentProcessGuid": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
        "ProcessId": "600", "ParentProcessId": "512",
    }).model_copy(update={"id": "child", "ts": START + timedelta(minutes=30)})
    unrelated = _event(1, data={"ProcessId": "700", "ParentProcessId": "512"}).model_copy(
        update={"id": "unrelated", "ts": START + timedelta(minutes=20)}
    )
    args = ProcessTreeArgs(host="ws01", process_id=512, start=START, end=END)

    selected, reason = PivotExecutor._select_windows_process_tree([root, child, unrelated], args, root.ts)

    assert {event.id for event in selected} == {"root", "child"}
    assert reason is None


def test_mixed_source_process_tree_applies_windows_fences_without_dropping_linux_events():
    windows = _event(1, data={"ProcessId": "512"}).model_copy(
        update={"id": "windows", "ts": START + timedelta(minutes=10)}
    )
    linux = windows.model_copy(update={
        "id": "linux", "normalizer": "lab-ecs@9",
        "fields": {
            "process.pid": windows.fields["process.pid"],
            "process.ppid": windows.fields.get("process.ppid"),
        },
    })
    args = ProcessTreeArgs(host="ws01", process_id=512, start=START, end=END)

    selected, reason = PivotExecutor._select_process_tree_by_os([linux, windows], args, windows.ts)

    assert {event.id for event in selected} == {"linux", "windows"}
    assert reason == "process_tree PID fence evidence unavailable"
