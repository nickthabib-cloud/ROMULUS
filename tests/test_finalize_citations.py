"""Aggregate rules that choose their cited witnesses at finalize publish no broken citation.

A witness chosen at finalize may come from a partition read long before; its raw record is gone from the sweep's
memory. A rule either keeps the witness's raw record itself (it hands it over as the match's raw copies), keeps it on
the sweep's event stage, or marks the witness compact so the publish path finds a copy the hunt already retained or
fetches the body from the source by native id. A compact witness without the mark has no path to a raw copy and is
cited as "raw copy missing", which makes the whole report not finalizable.

Each case drives a registered rule through the real sweep over two partitions, with the first and last witnesses in
different partitions, and resolves every citation of every finding exactly as the report manifest does.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from romulus.hunt import sweep as sw
from romulus.hunt.publish import SourceCitationFetcher, WindowsCitationFetcher
from romulus.report.manifest import _citations
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from tests import test_sweep as ts
from tests.fixtures import zeek_ics as zi
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_sweep_e2e import _repo

WINDOW = Window(start=ts.START, end=ts.START + timedelta(minutes=10))
CONTRACT_FIELDS = {"@timestamp": "date", "event.dataset": "keyword", "event.provider": "keyword"}


def run(tmp_path, monkeypatch, batches, pack=None, *, serve_ids=True, site_facts=None):
    """Sweep one network target whose partitions return `batches` in turn, with `pack` or the whole registered pack.
    The source serves by-id citation fetches from the same records unless `serve_ids` is false."""
    pending = list(batches)
    every = [hit for batch in batches for hit in batch]
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: ts._complete(intent, pending.pop(0)))

    class Source:
        version = "test"
        settings = ts.FakeClient.settings

        def search(self, index, body):
            if not serve_ids:
                return {"hits": {"hits": []}}
            wanted = body["query"]["bool"]["filter"][0]["ids"]["values"]
            return {"hits": {"hits": [hit for hit in every if hit["_index"] == index and hit["_id"] in wanted]}}

    contract = contract_from_types("net", CONTRACT_FIELDS, role="network", os_family="unknown")
    repo = _repo()
    hunt = sw.Sweep(repo, Source(), "h1", WINDOW, {"net": contract}, stage_dir=tmp_path, site_facts=site_facts)
    source = hunt.client
    if pack is not None:
        hunt.pack = pack
    for playbook in pack or ():
        # bound as the sweep binds its own pack
        playbook.spill_dir, playbook.budget, playbook.window_start = tmp_path, hunt.budget, WINDOW.start
        playbook.window_end = WINDOW.end
        playbook.citation_fetcher = (WindowsCitationFetcher(source) if hasattr(playbook, "citation_fields")
                                     else SourceCitationFetcher(source))
    hunt._profiles = {"net": {"role": "network", "datasets": {}}}
    step = (WINDOW.end - WINDOW.start) / len(batches)
    try:
        for i, batch in enumerate(batches):
            part = Window(start=WINDOW.start + step * i, end=WINDOW.start + step * (i + 1))
            hunt.run_partition("net", contract, [], part, est=len(batch), any_of=[])
        hunt.finalize()
    finally:
        hunt.close_stage()
    return repo, hunt


def citations(repo):
    out = {}
    for candidate in repo.candidates("h1"):
        out.setdefault(candidate["rule_id"], []).append((candidate, _citations(repo, candidate)))
    return out


def ics_discovery_batches():
    """Six BACnet who-is requests from one client to six devices within ten minutes, three per partition."""
    early, late = [], []
    for n in range(6):
        record = zi.ROWS["bacnet_discovery"].with_(uid=f"Cbacdisc{n:09d}", **{
            "id.resp_h": f"10.0.1.{n + 1}", "destination_h": f"10.0.1.{n + 1}", "id.orig_p": 47000 + n,
            "source_p": 47000 + n})
        record = type(record)(record.log, record.zeek, ts=zl.T0 + (40 * n if n < 3 else 300 + 40 * n))
        (early if n < 3 else late).append(zi.hit(record, "malcolm", nid=f"bacnet-who-is-{n}"))
    return [early, late]


def test_ics_discovery_fan_out_cites_retained_records(tmp_path, monkeypatch):
    from romulus.detect.ics import RemoteDiscovery
    repo, hunt = run(tmp_path, monkeypatch, ics_discovery_batches(), [RemoteDiscovery()])
    assert hunt.stats["errors"] == 0
    [(candidate, cited)] = citations(repo)["ics.remote_discovery"]
    assert candidate["lane"] == "lead"
    # witnesses from both partitions, every one resolved to a retained raw record
    assert {c["native_id"] for c in cited} & {f"bacnet-who-is-{n}" for n in range(3)}
    assert {c["native_id"] for c in cited} & {f"bacnet-who-is-{n}" for n in range(3, 6)}
    assert cited and all(c["status"] == "retained" for c in cited), cited


@pytest.mark.xfail(strict=True, reason="a compact witness whose body the source cannot serve at publication is still "
                                       "cited without a raw copy (rules that rely on the by-id fetch)")
def test_ics_discovery_when_the_source_cannot_serve_its_witnesses(tmp_path, monkeypatch):
    from romulus.detect.ics import RemoteDiscovery
    repo, _hunt = run(tmp_path, monkeypatch, ics_discovery_batches(), [RemoteDiscovery()], serve_ids=False)
    [(candidate, cited)] = citations(repo)["ics.remote_discovery"]
    assert "Citation body not retrieved" in candidate["claim"]
    assert all(c["status"] == "retained" for c in cited)


def lateral_rows():
    """Zeek lateral-movement, rate and share rows that the registered rules report (tests/test_zeek_lateral_sweep.py)."""
    from tests.test_zeek_admin_share_pe import FILES, PE
    from tests.test_zeek_admin_share_pe import SMB as SHARE
    from tests.test_zeek_rate_rules import rows_for
    rows = [zl.DCE_RPC, zl.DCE_RPC.with_(uid="Creplication000001", endpoint="drsuapi", operation="DRSGetNCChanges"),
            zl.DCE_RPC.with_(uid="Ccoercion00000001", endpoint="efsrpc", operation="EfsRpcOpenFileRaw"),
            zl.RDP.with_(**{"id.orig_h": "203.0.113.25"}), zl.RDP.with_(uid="CrdpInside0000001"), zl.RFB,
            zl.KERBEROS, SHARE, FILES, PE]
    for name, count, distinct in [("ZerologonRate", 50, True), ("Rc4TgsFanout", 10, True),
                                  ("KerberosPrincipalEnumeration", 20, True), ("NtlmPasswordSpray", 10, True)]:
        rows.extend(rows_for(name, count, distinct=distinct, success=name == "NtlmPasswordSpray"))
    rows.extend(zl.DCE_RPC.with_(uid=f"Csessenum{n:08d}", endpoint="srvsvc", operation="NetrSessionEnum",
                                 **{"id.resp_h": f"10.0.7.{n}"}) for n in range(25))
    return [zl.malcolm(row, f"lateral-{n}") for n, row in enumerate(rows)]


def mixed_batches():
    """Two partitions of network records that registered aggregate rules report at finalize: service names seen in
    both, an ICS discovery fan-out split across both, and a lateral-movement slice read in the first only."""
    from tests.test_service_catalog_citations import partitions
    services_early, services_late = partitions()["net"]
    ics_early, ics_late = ics_discovery_batches()
    return [services_early + ics_early + lateral_rows(), services_late + ics_late]


def mixed_site():
    from romulus.site import COLLECTION_SCHEMA, validate_site_content
    return validate_site_content({"schema": COLLECTION_SCHEMA, "internal_networks": ["10.0.0.0/8"],
                                  "domain_controller_addresses": [zl.DC], "management_hosts": [zl.WS]})


# Finalize-published rules this corpus must exercise, so the guard below cannot pass on an empty pack run.
EXERCISED = {"network.service_catalog", "ics.remote_discovery", "net.rpc_replication_call", "net.ntlm_password_spray",
             "net.kerberos_rc4_service_fanout", "net.netlogon_authentication_burst", "net.rpc_host_enumeration_fanout",
             "net.smb_admin_share_pe", "net.kerberos_principal_enumeration"}


def test_the_registered_pack_publishes_no_broken_citation_at_finalize(tmp_path, monkeypatch):
    repo, hunt = run(tmp_path, monkeypatch, mixed_batches(), site_facts=mixed_site())
    assert hunt.stats["errors"] == 0
    found = citations(repo)
    assert EXERCISED <= set(found), sorted(found)
    failed = [c["rule_id"] for c in repo.rule_cells("h1") if c["state"] == "executed_failed"]
    assert failed == []
    broken = [(rule, item["native_id"], item["status"]) for rule, items in found.items()
              for _candidate, cited in items for item in cited if item["status"] != "retained"]
    assert broken == []


@pytest.mark.xfail(strict=True, reason="rules whose finalize witnesses rely on the by-id fetch at publication still "
                                       "cite a record without a raw copy when the source cannot serve it")
def test_the_registered_pack_when_the_source_cannot_serve_finalize_witnesses(tmp_path, monkeypatch):
    repo, _hunt = run(tmp_path, monkeypatch, mixed_batches(), site_facts=mixed_site(), serve_ids=False)
    broken = [rule for rule, items in citations(repo).items() for _candidate, cited in items
              for item in cited if item["status"] != "retained"]
    assert broken == []


def test_an_authentication_witness_is_fetched_once_and_never_stored_unverified():
    """A Windows burst witness kept by reference (no digest) is left to the Windows citation pass, which checks the
    fetched body field by field. Marked compact as well, the digest-checked fetch would fetch it a second time and
    accept any body for a reference that records no digest."""
    from datetime import UTC, datetime

    from romulus.detect.base import Match
    from romulus.evidence.typed import RawRef, TypedEvent, fv
    from romulus.hunt.citations import AUTH_WITNESS_NOTE_PREFIX, COMPACT_CITATION_NOTE

    witness = TypedEvent(id="burst-1", family="auth", ts=datetime(2024, 11, 18, 14, tzinfo=UTC), host="dc1",
                         fields={"user.name": fv("alice", "w1:winlog.event_data.TargetUserName")},
                         raw=[RawRef(target="winlogbeat-x", native_id="w1")], normalizer="windows-ecs@23",
                         caveats=[AUTH_WITNESS_NOTE_PREFIX + "; compact recorded fields and native reference retained."])
    match = Match("synthetic.burst", "claim", "observed_action", [witness], [], witness.ts, "high", "lead", "medium")
    sw.Sweep._mark_uncopied(match, {})
    assert COMPACT_CITATION_NOTE not in match.events[0].caveats

    class Source:
        searches = 0

        def search(self, index, body):
            type(self).searches += 1
            # a body that is not the cited record: the field-by-field check must refuse it
            return {"hits": {"hits": [{"_index": "winlogbeat-x", "_id": "w1", "_source": {"unrelated": True}}]}}

    WindowsCitationFetcher(Source()).hydrate(match, {})
    assert Source.searches == 1
    assert match.raw_copies == {} and match.events[0].caveats[0].startswith(AUTH_WITNESS_NOTE_PREFIX)
