"""Synthetic profiles use Elastic exists/count semantics and NXLog flat Windows field names.

https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-exists-query
https://docs.nxlog.co/integrate/windows-eventlog.html
No corpus records are used. Profile classification must preserve Linux retrieval beside flat Windows rows.
"""
from datetime import UTC, datetime

import pytest

from romulus.errors import SourceError
from romulus.hunt.sweep import Sweep
from romulus.sources.compile import build_query
from romulus.sources.models import SearchIntent, Window
from romulus.sources.profile import build_profile
from tests.test_host_shapes_profile import mapping
from tests.throughput_fixture import _matches

FLAT = {"Channel": "text", "Channel.keyword": "keyword", "EventID": "long", "SourceName": "text",
        "Hostname": "text", "Hostname.keyword": "keyword"}
COMMON = {"@timestamp": "date", "event.dataset": "keyword", "event.module": "keyword", "host.name": "keyword",
          "process.executable": "keyword", "user.name": "keyword", "message": "text"}
WINDOW = Window(start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC))


class ProfileClient:
    settings = type("Settings", (), {"es_flavor": "elasticsearch"})()
    version = "8.19.0"

    def __init__(self, datasets, *, count=3, failed=False, linux_marker=False, network=False):
        self.datasets, self.count, self.failed = datasets, count, failed
        self.fields = {**COMMON, **FLAT}
        if linux_marker:
            self.fields["auditd.data.syscall"] = "keyword"
        if network:
            self.fields.update({"source.ip": "ip", "destination.ip": "ip", "event.provider": "keyword"})

    def mapping(self, _target):
        return mapping(self.fields)

    def search(self, _target, body):
        if "aggs" not in body:
            if body.get("size") == 0:
                if self.failed:
                    raise SourceError("synthetic marker count failure")
                return {"hits": {"total": {"value": self.count, "relation": "eq"}}}
            # There are no unstructured text rows in this synthetic collection.
            return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}
        host_agg = body["aggs"].get("hosts", {})
        paged = "composite" in host_agg
        buckets = [{"key": {"host": "ws01"} if paged else "web01", "doc_count": 3 if paged else 37}]
        return {"hits": {"total": {"value": 40, "relation": "eq"}}, "aggregations": {
            "ds": {"buckets": [{"key": name, "doc_count": count} for name, count in self.datasets.items()]},
            "hosts": {"buckets": buckets}, "tmin": {}, "tmax": {}}}


@pytest.mark.parametrize("linux_marker", [False, True])
@pytest.mark.parametrize("failed", [False, True])
def test_live_linux_dataset_remains_linux_and_selects_auditd_beside_nxlog(linux_marker, failed):
    profile, contract = build_profile(ProfileClient({"auditd.log": 37}, linux_marker=linux_marker, failed=failed), "mixed")
    assert profile.role == contract.role == "host"
    assert profile.os_family == contract.os_family == "linux"
    assert contract.nxlog_mixed
    assert contract.fields["host.name"].native == "host.name"
    assert profile.datasets["auditd.log"] == 37
    assert any("Windows classification unverified" in note for note in profile.notes) is failed

    sweep = Sweep(None, None, "synthetic", WINDOW, {"mixed": contract})
    sweep.pack = []
    query = build_query(SearchIntent(kind="raw", target="mixed", window=WINDOW,
        filters=sweep._filters_for("mixed", contract), any_of=sweep._any_of_for("mixed", contract)), contract)
    auditd = {"@timestamp": "2026-01-01T01:00:00Z", "event": {"dataset": "auditd.log", "module": "auditd"},
              "host": {"name": "web01"}, "auditd": {"data": {"syscall": "execve"}}}
    nxlog = {"@timestamp": "2026-01-01T01:00:01Z", "Channel": "Security", "EventID": 4688, "Hostname": "ws01"}
    assert _matches(query, auditd, "@timestamp"), "live profiling must not remove Linux audit records from retrieval"
    assert _matches(query, nxlog, "@timestamp"), "flat Windows records must remain selected beside Linux records"


def test_live_linux_only_mapping_markers_are_not_promoted_by_positive_windows_count():
    profile, contract = build_profile(ProfileClient({}, linux_marker=True), "mixed")
    assert profile.os_family == contract.os_family == "linux"
    assert contract.nxlog_mixed


@pytest.mark.parametrize("datasets", [{"windows.security": 3}, {}])
def test_live_windows_only_profile_retains_windows_with_positive_record_evidence(datasets):
    profile, contract = build_profile(ProfileClient(datasets), "windows")
    assert profile.os_family == contract.os_family == "windows"
    assert not contract.nxlog_mixed
    assert contract.fields["host.name"].native == "Hostname"
    assert not any("Windows classification unverified" in note for note in profile.notes)


def test_live_zero_windows_count_vetoes_windows_mapping_and_preserves_inventory_note():
    client = ProfileClient({}, count=0)
    client.fields["Hostname"] = "keyword"
    client.fields.pop("Hostname.keyword")
    profile, contract = build_profile(client, "empty-windows-template")
    assert profile.os_family == contract.os_family == "linux"
    assert contract.fields["host.name"].native == "host.name"
    assert profile.hosts == {"web01": 37}
    assert any("counted by NXLog's Hostname" in note for note in profile.notes)
    assert not contract.host_inventory_complete


def test_live_failed_windows_count_preserves_conservative_mapping_hint_with_note():
    profile, contract = build_profile(ProfileClient({}, failed=True), "unverified")
    assert profile.os_family == contract.os_family == "windows"
    assert not contract.nxlog_mixed
    assert any("Windows classification unverified" in note for note in profile.notes)


@pytest.mark.parametrize("count", [0, 3])
def test_live_network_dataset_never_gains_windows_classification_or_aliases(count):
    profile, contract = build_profile(ProfileClient({"zeek.connection": 37}, count=count, network=True), "network")
    assert profile.role == contract.role == "network"
    assert profile.os_family == contract.os_family == "unknown"
    assert not contract.nxlog_mixed
    assert contract.fields["host.name"].native == "host.name"
    assert contract.fields["event.provider"].native == "event.provider"
    assert (profile.model_dump().get("windows_not_assessed") or {}).get("records", 0) == count


def test_live_profile_compiled_sweep_query_keeps_linux_audit_records():
    _profile, contract = build_profile(ProfileClient({"auditd.log": 37}, linux_marker=True), "mixed")
    sweep = Sweep(None, None, "synthetic", WINDOW, {"mixed": contract})
    sweep.pack = []
    query = build_query(SearchIntent(kind="raw", target="mixed", window=WINDOW,
        filters=sweep._filters_for("mixed", contract), any_of=sweep._any_of_for("mixed", contract)), contract)
    auditd = {"@timestamp": "2026-01-01T01:00:00Z", "event": {"dataset": "auditd.log", "module": "auditd"},
              "host": {"name": "web01"}, "auditd": {"data": {"syscall": "execve"}}}
    assert _matches(query, auditd, "@timestamp"), "an auditd event must remain inside the sweep's retrieval query"
