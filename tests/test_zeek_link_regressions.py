"""Real expansion and pivot regressions for Zeek joins and host witnesses."""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from romulus.config import Settings
from romulus.hunt.expansion import ExpansionEngine
from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkResult, LinkWindow
from romulus.hunt.pivot import PivotExecutor
from romulus.sources.es import ElasticClient
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from romulus.store.db import make_engine, migrate
from romulus.store.repo import Repo
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl
from tests.test_expansion_engine import event as process_event
from tests.test_zeek_links import NativePivot, normalize
from tests.zeek_source_support import ZeekES


def host_hit(name, stamp, identity):
    raw = (
        f'type=USER_LOGIN msg=audit({stamp}:1): pid=900 uid=0 auid=1001 '
        'ses=42 acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.8 res=success'
    )
    return {"_index": "hosts", "_id": str(identity), "_source": {
        "@timestamp": zf.iso_ms(stamp), "host": {"name": name},
        "event": {"dataset": "linux.audit", "original": raw},
    }}


@contextmanager
def real_pivot(tmp_path, hits, hosts=None):
    native = NativePivot("malcolm", hits)
    contracts = {"network": native.contracts["network"].model_copy(
        update={"time_field": "@timestamp"})}
    docs = {"network": hits}
    if hosts is not None:
        docs["hosts"] = hosts
        contracts["hosts"] = contract_from_types("hosts", {
            "@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword",
        }, role="host", os_family="linux",
            hosts=tuple(sorted({row["_source"]["host"]["name"] for row in hosts})))
    backend = ZeekES(docs, {target: "@timestamp" for target in docs})
    client = ElasticClient(Settings(home=tmp_path), transport=backend.transport())
    engine = make_engine(tmp_path / "hunt.db")
    migrate(engine)
    repo = Repo(engine)
    repo.create_hunt("h", {"targets": list(docs)}, "digest", "test")
    pivot = PivotExecutor(repo, client, "h", contracts, stage_dir=tmp_path / "stage")
    try:
        yield repo, pivot, backend
    finally:
        engine.dispose()


def seed(repo, root):
    repo.save_evidence("h", [root], {}, None)
    repo.save_candidate({
        "id": "finding", "hunt_id": "h", "rule_id": "host.web_shell",
        "rule_version": "1", "claim": "observed anchor", "claim_type": "observed_action",
        "event_ids": [root.id], "predicate_fields": [], "entities": [], "ts": root.ts,
        "severity": "critical", "confidence": "high", "lane": "urgent", "priority": 100.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })


def expand(repo, pivot, root, kind, monkeypatch):
    # Exercise real scheduling, fetching and persistence with one requested reach.
    # Other independent reaches cannot spend this regression's query budget.
    monkeypatch.setattr("romulus.hunt.expansion.TIER_PLAN",
                        (("test", (kind,), "anchor ±5 min"),))
    seed(repo, root)
    window = Window(start=root.ts - timedelta(hours=1), end=root.ts + timedelta(hours=3))
    ExpansionEngine(repo, "h", window, LinkFetcher(pivot, window.start, window.end),
                    max_depth=1, max_source_queries=1000).run()
    return [link for link in repo.expansion_links("h") if link["link_type"] == kind]


def linked(pivot, root, kind):
    anchor = LinkAnchor(finding_id="finding", ts=root.ts, events=[root], event_ids=[root.id])
    window = LinkWindow(label="test", start=root.ts - timedelta(minutes=5),
                        end=root.ts + timedelta(minutes=5))
    return LinkFetcher(pivot, window.start, window.end).fetch(anchor, kind, window)


@pytest.mark.parametrize("kind", ["address_host", "zeek_file", "zeek_uid"])
def test_expansion_follows_each_key_to_a_distinct_result(tmp_path, monkeypatch, kind):
    hosts = None
    if kind == "address_host":
        first = zl.DHCP.with_(assigned_addr=zf.Conn().orig_h, host_name="first", lease_time=1800)
        second = first.with_(assigned_addr=zf.Conn().resp_h, host_name="second",
                             mac="02:00:00:00:00:22")
        anchor_hit = zf.malcolm(replace(zf.Conn(), ts=first.ts + 60), "anchor")
        hits = [anchor_hit, zl.malcolm(first, "first"), zl.malcolm(second, "second")]
        hosts = [host_hit(name, first.ts + 60, index) for index, name in enumerate(("first", "second"))]
        expected = {"10.0.0.5": "first", "203.0.113.10": "second"}
    elif kind == "zeek_file":
        anchor_hit = zl.malcolm(zl.HTTP.with_(resp_fuids=["Fone", "Ftwo"]), "anchor")
        hits = [anchor_hit, zl.malcolm(zl.FILES.with_(fuid="Fone"), "one"),
                zl.malcolm(zl.FILES.with_(fuid="Ftwo"), "two"),
                zf.malcolm(replace(zf.Conn(), uid=zl.UID_HTTP, ts=zl.HTTP.ts), "conn")]
        expected = {"Fone": normalize("malcolm", hits[1]).id,
                    "Ftwo": normalize("malcolm", hits[2]).id}
    else:
        anchor_hit = zl.malcolm(zl.FILES_50.with_(uid=None, conn_uids=["Cone", "Ctwo"]), "anchor")
        hits = [anchor_hit, *[zf.malcolm(replace(zf.Conn(), uid=uid, ts=zl.FILES.ts), uid)
                             for uid in ("Cone", "Ctwo")]]
        expected = {"Cone": normalize("malcolm", hits[1]).id,
                    "Ctwo": normalize("malcolm", hits[2]).id}
    root = normalize("malcolm", anchor_hit)
    with real_pivot(tmp_path, hits, hosts) as (repo, pivot, _backend):
        results = expand(repo, pivot, root, kind, monkeypatch)
        field = {"address_host": "ip", "zeek_file": "fuid", "zeek_uid": "uid"}[kind]
        by_key = {result["key"][field]: result for result in results}
        assert set(by_key) == set(expected)
        assert len({result["id"] for result in results}) == 2
        for key, wanted in expected.items():
            rows = repo.events_by_ids(by_key[key]["event_ids"])
            if kind == "address_host":
                assert any(row["event"]["host"] == wanted for row in rows)
            else:
                assert wanted in by_key[key]["event_ids"]


def test_expansion_caps_5000_carrier_keys_and_shares_query_and_row_limits(tmp_path, monkeypatch):
    anchor_hit = zl.malcolm(zl.FILES_50.with_(
        uid=None, conn_uids=[f"C{i:04d}" for i in range(5000)]), "anchor")
    root = normalize("malcolm", anchor_hit)
    with real_pivot(tmp_path, [anchor_hit]) as (repo, pivot, _backend):
        results = expand(repo, pivot, root, "zeek_uid", monkeypatch)
        reasons = [reason for row in repo.expansion_anchors("h") for reason in row["reasons"]]
        assert any("limit 1000" in reason and "key" in reason.lower() for reason in reasons)
        assert len({row["key"]["uid"] for row in results}) <= 1000
        assert repo.expansion_source_queries("h") <= 128
        assert sum(cell["returned"] or 0 for row in results for cell in row["coverage"]) <= 10000
        assert repo.expansion_anchors("h")[0]["status"] == "expanded_partial"


def test_interim_anchor_rebuilds_final_span_and_joins_late_analyzer(tmp_path):
    interim = zf.malcolm(replace(zf.Conn(), uid=zl.UID_HTTP, ts=zl.HTTP.ts, duration=60),
                         "interim", interim=True)
    final = zf.malcolm(replace(zf.Conn(), uid=zl.UID_HTTP, ts=zl.HTTP.ts, duration=7200), "final")
    late = zl.malcolm(replace(zl.HTTP, ts=zl.HTTP.ts + 3600), "late")
    with real_pivot(tmp_path, [interim, final, late]) as (_repo, pivot, _backend):
        result = linked(pivot, normalize("malcolm", interim), "zeek_uid")
        assert result.status == "complete", result.reasons
        assert normalize("malcolm", final).id in result.event_ids
        assert normalize("malcolm", late).id in result.event_ids


def test_only_interim_connection_names_the_unsearched_future(tmp_path):
    interim = zf.malcolm(replace(zf.Conn(), uid=zl.UID_HTTP, ts=zl.HTTP.ts, duration=60),
                         "interim", interim=True)
    with real_pivot(tmp_path, [interim]) as (_repo, pivot, _backend):
        result = linked(pivot, normalize("malcolm", interim), "zeek_uid")
        assert result.status == "partial"
        assert "connection still open at the last interim record; later records not searched" in result.reasons


def test_host_witness_is_small_nearest_first_and_probe_overflow_is_complete(tmp_path):
    lease = zl.DHCP.with_(assigned_addr=zf.Conn().orig_h, host_name="first", lease_time=86400 * 8)
    lease = replace(lease, ts=zf.Conn().ts - 6 * 86400)
    anchor_hit = zf.malcolm(zf.Conn(), "anchor")
    old = [host_hit("first", zf.Conn().ts - 5 * 86400 + i * 60, i) for i in range(100)]
    nearest = host_hit("first", zf.Conn().ts + 30, "nearest")
    recent = [host_hit("first", zf.Conn().ts - 40 + i, f"recent-{i}") for i in range(40)]
    hosts = [*old, *recent, nearest]
    with real_pivot(tmp_path, [zl.malcolm(lease, "lease"), anchor_hit], hosts) as (repo, pivot, _backend):
        result = linked(pivot, normalize("malcolm", anchor_hit), "address_host")
        witness_rows = [row["event"] for row in repo.events_by_ids(result.event_ids)
                        if row["event"]["host"] == "first"]
        assert result.status == "complete", result.reasons
        assert 1 <= len(witness_rows) <= 20
        assert any(datetime.fromisoformat(row["ts"]).timestamp() == zf.Conn().ts + 30
                   for row in witness_rows)
        assert not any("cap:" in reason for reason in result.reasons)


def test_dhcp_without_searchable_host_contract_names_host_coverage(tmp_path):
    lease = zl.DHCP.with_(assigned_addr=zf.Conn().orig_h, host_name="first", lease_time=1800)
    anchor_hit = zf.malcolm(replace(zf.Conn(), ts=lease.ts + 60), "anchor")
    with real_pivot(tmp_path, [zl.malcolm(lease, "lease"), anchor_hit]) as (_repo, pivot, _backend):
        result = linked(pivot, normalize("malcolm", anchor_hit), "address_host")
        assert result.status == "partial"
        assert any("host" in reason.lower() and "searchable" in reason.lower() for reason in result.reasons)
        assert not any("source key or sensor is not searchable" in reason for reason in result.reasons)


@pytest.mark.parametrize("kind, publishes", [("address_host", False), ("host_after_anchor", True)])
def test_host_witness_supports_identity_without_running_direct_detection(tmp_path, kind, publishes):
    anchor_hit = zf.malcolm(zf.Conn(), "anchor")
    root = normalize("malcolm", anchor_hit)
    witness = process_event("credential-read", host="first", ts=root.ts - timedelta(days=2),
                            argv=["/usr/bin/cat", "/etc/shadow"])
    with real_pivot(tmp_path, [anchor_hit]) as (repo, pivot, _backend):
        seed(repo, root)
        repo.save_evidence("h", [witness], {}, None)
        window = Window(start=root.ts - timedelta(hours=1), end=root.ts + timedelta(hours=3))
        engine = ExpansionEngine(repo, "h", window, LinkFetcher(pivot, window.start, window.end))
        result = LinkResult(
            id="witness-link", anchor_id="finding", link_type=kind, strength="inferred",
            window=LinkWindow(label="identity witness", start=root.ts - timedelta(days=7),
                              end=root.ts + timedelta(minutes=5)),
            key={"ip": "10.0.0.5"}, status="complete", event_ids=[witness.id],
            evidence_ids=[root.id, witness.id], task_ids=[], coverage=[], query_spend=0,
        )
        engine._persist_link(result)
        engine._evaluate(repo.candidate("finding"), result)
        findings = [row for row in repo.candidates("h") if row["rule_id"] == "host.credential_store_read"]
        assert bool(findings) is publishes
        assert repo.expansion_link(result.id)["evaluated"]
        assert repo.events_by_ids([witness.id])


def test_certificate_mixed_case_anchor_searches_lowercase_source_fingerprint(tmp_path):
    anchor_hit = zl.malcolm(zl.SSL, "anchor")
    certificate = zl.malcolm(replace(zl.X509, ts=zl.SSL.ts - 86400), "cert")
    root = normalize("malcolm", anchor_hit)
    fingerprint = root.get("tls.server.cert_chain_fps")[0]
    root.fields["tls.server.cert_chain_fps"].value = [
        "".join(char.upper() if index % 2 else char.lower() for index, char in enumerate(fingerprint))
    ]
    with real_pivot(tmp_path, [anchor_hit, certificate]) as (_repo, pivot, _backend):
        result = linked(pivot, root, "certificate")
        assert normalize("malcolm", certificate).id in result.event_ids
        assert result.status == "complete", result.reasons
