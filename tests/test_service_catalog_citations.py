"""Every record a service-name finding cites is retained by the hunt, including witnesses chosen at finalize.

The rule keeps at most a first and a last witness per (service, source) and per service fleet. A witness chosen at
finalize can come from a partition read long before, whose raw records are gone from the sweep's memory. The rule
keeps the witness's raw records beside it on disk, so the finding cites retained records without asking the source
again. These tests run the real sweep over two partitions with a source that answers no by-id citation fetch: a
citation can only resolve from what the rule kept.
"""
from __future__ import annotations

import json
import zlib
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect import service_catalog as sc
from romulus.detect.bounded import StateBudget, StateExhausted
from romulus.detect.netdef import SiteNetworks, current, install
from romulus.evidence.typed import RawRef, TypedEvent, fv
from romulus.hunt import sweep as sw
from romulus.hunt.citations import COMPACT_CITATION_NOTE
from romulus.report.manifest import _citations
from romulus.site import COLLECTION_SCHEMA, validate_site_content
from romulus.sources.models import Window
from romulus.sources.profile import contract_from_types
from tests import test_sweep as ts
from tests.fixtures import zeek_logs as zl
from tests.test_zeek_sweep_e2e import _repo

START = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)
SPLIT = START + timedelta(minutes=5)
END = START + timedelta(minutes=10)


def row_at(row, at, **changes):
    changed = row.with_(**changes)
    return type(changed)(changed.log, changed.zeek, ts=at)


def eve_dns(nid, client, name, at):
    when = datetime.fromtimestamp(at, UTC).isoformat().replace("+00:00", "Z")
    record = {"timestamp": when, "event_type": "dns", "src_ip": client, "src_port": 40000, "dest_ip": "10.0.0.53",
              "dest_port": 53, "proto": "UDP", "dns": {"type": "query", "id": 7, "rrname": name, "rrtype": "A"}}
    return {"_index": "logs-suricata.eve-default", "_id": nid, "_source": {
        "@timestamp": when, "host": {"name": "sensor-suricata"},
        "event": {"dataset": "suricata.eve.dns", "original": json.dumps(record)}}}


def arkime_tls(nid, client, host, at):
    first = int(at * 1000)
    return {"_index": "arkime_sessions3-241118", "_id": nid, "_source": {
        "firstPacket": first, "lastPacket": first + 4000, "ipProtocol": 6, "node": "sensor1",
        "protocol": ["tcp", "tls"], "network": {"community_id": f"1:{nid}="},
        "source": {"ip": client, "port": 50000, "bytes": 700, "packets": 6},
        "destination": {"ip": "198.51.100.40", "port": 443, "bytes": 1500, "packets": 5},
        "http": {"host": [host]}}}


T = zl.T0          # 2024-11-18T14:00:00.123Z, inside the first partition
LATE = T + 400.0   # inside the second partition


def partitions():
    """{target: (first partition hits, second partition hits)}: each service is seen by its producer in both. Plain
    Zeek JSON is its own declared target, as a site configures it."""
    early, late = [], []
    plain_early, plain_late = [], []
    for shape, name in (("malcolm", "a1.ngrok-free.app"), ("elastic", "b2.trycloudflare.com"),
                        ("security_onion", "c3.serveo.net"), ("plain", "d4.localtonet.com")):
        writer = zl.WRITERS[shape]
        for n, (client, at, out) in enumerate((("10.0.0.5", T, early), ("10.0.0.6", T + 10, early),
                                               ("10.0.0.5", LATE, late), ("10.0.0.6", LATE + 10, late))):
            row = row_at(zl.DNS, at, uid=f"Cdns{shape[:3]}{n:09d}", query=name,
                         **{"id.orig_h": client, "id.resp_h": "10.0.0.53", "id.orig_p": 53000 + n})
            if shape == "plain":
                out = plain_early if out is early else plain_late
            out.append(writer(row, f"{shape}-dns-{n}"))
    # an approved service: its witnesses are never published while a partition is read
    for n, (at, out) in enumerate(((T + 20, early), (LATE + 20, late))):
        row = row_at(zl.SSL, at, uid=f"CsslAnyd{n:09d}", server_name="relay-7.net.anydesk.com",
                     **{"id.orig_h": "10.0.0.5", "id.orig_p": 51020 + n})
        out.append(zl.malcolm(row, f"malcolm-ssl-{n}"))
    for n, (at, out) in enumerate(((T + 30, early), (LATE + 30, late))):
        row = row_at(zl.HTTP, at, uid=f"ChttpHook{n:08d}", host="webhook.site",
                     **{"id.orig_h": "10.0.0.7", "id.orig_p": 51010 + n})
        out.append(zl.malcolm(row, f"malcolm-http-{n}"))
    for n, (at, out) in enumerate(((T + 40, early), (LATE + 40, late))):
        out.append(arkime_tls(f"arkime-{n}", "10.0.0.8", "tenant.screenconnect.com", at))
        out.append(eve_dns(f"eve-dns-{n}", "10.0.0.9", "upload.transfer.sh", at + 1))
    return {"net": (early, late), "zplain": (plain_early, plain_late)}


@pytest.fixture
def networks():
    previous = current()
    yield
    install(previous)


def sweep_two_partitions(tmp_path, monkeypatch, targets):
    serving = {}
    monkeypatch.setattr(sw, "execute", lambda client, intent, contract: ts._complete(intent, serving[intent.target]))

    class NoCitationSource:
        """The source answers the sweep's partitions but no by-id citation fetch: only kept copies can resolve."""
        fetches = 0

        def search(self, index, body):
            type(self).fetches += 1
            return {"hits": {"hits": []}}

    contracts = {"net": contract_from_types("net", {"@timestamp": "date", "event.dataset": "keyword",
                                                    "event.provider": "keyword"}, role="network", os_family="unknown"),
                 "zplain": contract_from_types("zplain", {"ts": "date"}, role="network", os_family="unknown")
                 .model_copy(update={"zeek_sensor": zl.SENSOR, "zeek_log": None})}
    facts = validate_site_content({"schema": COLLECTION_SCHEMA, "internal_networks": ["10.0.0.0/8"],
                                   "approved_remote_access": ["anydesk"]})
    repo = _repo()
    hunt = sw.Sweep(repo, NoCitationSource(), "h1", Window(start=START, end=END), contracts,
                    stage_dir=tmp_path, site_facts=facts)
    hunt._profiles = {"net": {"role": "network", "datasets": {}},
                      "zplain": {"role": "network", "kind": "plain_zeek", "zeek_sensor": zl.SENSOR, "datasets": {}}}
    try:
        # one target is read whole before the next, as the sweep reads them
        for target, (early, late) in targets.items():
            for window, hits in ((Window(start=START, end=SPLIT), early), (Window(start=SPLIT, end=END), late)):
                serving[target] = hits
                hunt.run_partition(target, contracts[target], [], window, est=len(hits), any_of=[])
        hunt.finalize()
    finally:
        hunt.close_stage()
    return repo, hunt


def test_witnesses_chosen_at_finalize_cite_retained_records_from_every_producer(tmp_path, monkeypatch, networks):
    targets = partitions()
    repo, hunt = sweep_two_partitions(tmp_path, monkeypatch, targets)
    assert hunt.stats["errors"] == 0
    cells = [c for c in repo.rule_cells("h1", rule_id=sc.ServiceCatalog.id) if c["target"] == "*"]
    assert cells and all(c["state"] != "executed_failed" for c in cells)
    found = {c["group_key"]: c for c in repo.candidates("h1") if c["rule_id"] == sc.ServiceCatalog.id}
    expected_fleets = {"ngrok|fleet", "cloudflare-tunnel|fleet", "serveo|fleet", "anydesk|fleet",
                       "webhook-site|fleet", "screenconnect|fleet", "transfer-sh|fleet", "localtonet|fleet"}
    assert expected_fleets <= set(found), sorted(found)
    late_ids = {hit["_id"] for _early, late in targets.values() for hit in late}
    finalize_witness_from_late_partition = 0
    for candidate in found.values():
        citations = _citations(repo, candidate)
        assert citations and all(c["status"] == "retained" for c in citations), (candidate["group_key"], citations)
        assert "Citation body not retrieved" not in candidate["claim"]
        finalize_witness_from_late_partition += any(c["native_id"] in late_ids for c in citations)
    # each service's last witness is from the second partition and was cited only at finalize
    assert finalize_witness_from_late_partition >= len(expected_fleets)
    # fleet members are internal source addresses, resolved to hosts by the ranking, never host names themselves
    for key, candidate in found.items():
        kind = (candidate["gate_results"] or {}).get("_fleet_member_kind")
        assert kind == ("internal_address" if key.endswith("|fleet") else None), (key, kind)
    # the approved service's fleet finding was never published live: both witnesses are kept copies
    anydesk = _citations(repo, found["anydesk|fleet"])
    assert {c["native_id"] for c in anydesk} == {"malcolm-ssl-0", "malcolm-ssl-1"}


def test_every_finding_of_the_sweep_has_no_broken_citation(tmp_path, monkeypatch, networks):
    repo, _hunt = sweep_two_partitions(tmp_path, monkeypatch, partitions())
    candidates = repo.candidates("h1")
    assert candidates
    broken = [(c["rule_id"], item) for c in candidates for item in _citations(repo, c)
              if item["status"].startswith("broken")]
    assert broken == []


# ---- the rule alone ---------------------------------------------------------------------------------------------

def event(n, source="10.0.0.1", name="abc.ngrok-free.app", ts=None):
    return TypedEvent(id=f"event-{n}", family="dns_query", ts=ts or START + timedelta(seconds=n), host=None,
                      fields={"source.ip": fv(source, "native.client"), "dns.question.name": fv(name, "native.q")},
                      raw=[RawRef(target="idx", native_id=str(n))], normalizer="synthetic@1")


def raw_for(events, size=0):
    return {ref.key: {"n": ref.native_id, "pad": "x" * size} for e in events for ref in e.raw}


@pytest.fixture
def rule(networks):
    install(SiteNetworks.from_lists(["10.0.0.0/8"]))
    instance = sc.ServiceCatalog()
    yield instance
    instance.close_spill()


def drive(rule, batches, size=0):
    out = []
    for batch in batches:
        rule.bind_raw(raw_for(batch, size), "idx")
        out.extend(rule.consume(batch))
    rule.bind_raw({})
    for match in rule.finalize():
        match.fleet_hosts = tuple(match.fleet_hosts)
        out.append(match)
    return out


def test_finalize_witnesses_carry_their_kept_raw_copies(rule):
    matches = drive(rule, [[event(1), event(2, "10.0.0.2")], [event(90), event(91, "10.0.0.2")]])
    finals = [m for m in matches if m.revision_reason or m.group_key.endswith("|fleet")]
    assert finals
    for match in finals:
        assert {ref.key for e in match.events for ref in e.raw} <= set(match.raw_copies)
        assert sc.WITNESS_NOTE in match.notes and COMPACT_CITATION_NOTE not in match.notes
        assert all(COMPACT_CITATION_NOTE in e.caveats for e in match.events)   # verified at publication
    fleet = next(m for m in matches if m.group_key == "ngrok|fleet")
    assert [e.id for e in fleet.events] == ["event-1", "event-91"]
    assert fleet.raw_copies == {"idx/1": {"n": "1", "pad": ""}, "idx/91": {"n": "91", "pad": ""}}
    assert "service_raw_copies" not in rule.__dict__.get("_cov_notes", {})


def test_a_copy_over_its_bound_is_not_kept_and_the_finding_says_its_body_is_fetched(rule, monkeypatch):
    monkeypatch.setattr(sc, "MAX_RAW_COPY_BYTES", 64)
    matches = drive(rule, [[event(1)], [event(90)]], size=4096)
    fleet = next(m for m in matches if m.group_key == "ngrok|fleet")
    assert fleet.raw_copies == {} and [e.id for e in fleet.events] == ["event-1", "event-90"]
    assert COMPACT_CITATION_NOTE in fleet.notes and sc.WITNESS_NOTE not in fleet.notes
    assert all(COMPACT_CITATION_NOTE in e.caveats and e.raw for e in fleet.events)
    assert "service_raw_copies" in rule.__dict__.get("_cov_notes", {}) and not rule.limits


def test_a_raw_copy_never_costs_a_source_its_membership_row(rule, monkeypatch):
    """A write refused for its bytes is retried without the copy before the source is refused."""
    calls = {"n": 0}
    original = sc.ServiceCatalog._write_witness

    def refuse_copies(spill, key, rank, witness):
        calls["n"] += 1
        if witness[1] is not None:
            raise StateExhausted("synthetic: no room for a citation copy")
        return original(spill, key, rank, witness)

    monkeypatch.setattr(sc.ServiceCatalog, "_write_witness", staticmethod(refuse_copies))
    matches = drive(rule, [[event(n, f"10.0.0.{n}") for n in range(1, 6)]])
    fleet = next(m for m in matches if m.group_key == "ngrok|fleet")
    assert fleet.fleet_host_count == 5 and fleet.fleet_hosts_complete
    assert rule.evaluated == 5 and not rule.capped and "service_state" not in rule.limits
    assert "service_raw_copies" in rule.__dict__.get("_cov_notes", {}) and calls["n"] == 10


def test_live_findings_keep_the_partition_copy_even_when_the_row_cannot_be_written(rule, tmp_path):
    rule.spill_dir = tmp_path
    rule.budget = StateBudget(tmp_path, disk_total=1024, reserve=0)
    rule.bind_raw(raw_for([event(1)]), "idx")
    [match] = list(rule.consume([event(1)]))
    assert match.events and set(match.raw_copies) == {"idx/1"}


@pytest.mark.slow
def test_kept_copies_live_on_disk_not_in_memory_at_20k_sources(tmp_path, networks):
    """20,000 sources with about 2 KB raw records each: Python memory stays flat while the spill grows."""
    import gc
    import tracemalloc
    from ipaddress import ip_address

    definition = SiteNetworks.from_lists(["10.0.0.0/8"])
    install(definition)
    for index in range(20_000):
        definition.is_internal(ip_address(0x0A000000 + index + 1))

    def measure(rows, directory):
        rule = sc.ServiceCatalog()
        rule.spill_dir = directory
        rule.budget = StateBudget(directory, disk_total=4 * 2**30, reserve=0)
        gc.collect()
        tracemalloc.start()
        try:
            for index in range(rows):
                batch = [event(index, str(ip_address(0x0A000000 + index + 1)))]
                # incompressible padding: the kept copy is about its raw size on disk
                rule.bind_raw({ref.key: {"n": ref.native_id, "pad": zlib.crc32(str(index).encode()).to_bytes(4, "big").hex() * 256}
                               for ref in batch[0].raw}, "idx")
                for _ in rule.consume(batch):
                    pass
            kept = 0
            for match in rule.finalize():
                kept += len(match.raw_copies)
                if match.group_key.endswith("|fleet"):
                    assert sum(1 for _ in match.fleet_hosts) == rows
            peak = tracemalloc.get_traced_memory()[1]
            return {"rows": rows, "peak": peak, "kept": kept, "disk": rule._spill.path.stat().st_size}
        finally:
            tracemalloc.stop()
            rule.close_spill()

    small = measure(2_000, tmp_path / "small")
    large = measure(20_000, tmp_path / "large")
    assert small["kept"] >= 2_000 and large["kept"] >= 20_000
    assert large["peak"] <= small["peak"] + 2_000_000
    assert large["disk"] > small["disk"] * 5
