"""Throughput work must not change a hunt's result.

A synthetic multi-source record set (tests/throughput_fixture.py) runs through the real sweep, expansion, context
pass and report manifest against an in-memory Elasticsearch, with partition and pivot sizes small enough that the
data forces pre-splits, capped fetches that split again, capped pivot leaves and sampling. Every stored row and
the manifest are compared with digests captured from the implementation before the throughput changes, so a
faster path that changes any finding, citation, coverage cell, link result or manifest field fails here.

If a change is meant to alter results, it is not a throughput change: review it as a semantic change, then record
the new digests below with the reason.
"""
import hashlib
import json

import pytest

from romulus.evidence.normalize import BootIntervals, normalize_hits
from romulus.hunt.pivot import PivotExecutor
from tests import throughput_fixture as tf

# Reference digests of the synthetic fixture's results; any change to hunt output changes them. Expansion task
# ids include the query scope, so links and raw copies reference those ids, and the report's incident graph marks
# each edge's kind; the deterministic findings are unchanged.
# Rule versions bumped when detector state moved to disk-backed stores change rule_cells, candidates and
# manifest only: with each rule's version set back, every digest matches the reference before them.
# The per-site internal-network definition then changes, under the default definition the fixture runs with:
# - rule_cells, manifest: the cells of the direction-dependent rules whose partitions held records skipped or
#   judged for their direction go from complete to partial (matched to match_on_partial) with the reason
#   "internal networks not configured for this site; direction assumed from RFC 1918 defaults"; the report's
#   coverage rows and gaps for those rules follow.
# - rule_cells, candidates, manifest: those six rules, and the four rules whose wording changed, carry new
#   versions; "non-private address" becomes "an address outside the site's internal networks" in claims and
#   titles, and net.outbound_volume_asymmetry's positive-only reason names the definition.
# - tasks, audit, expansion, manifest: expansion also resolves a network anchor's endpoints the default reads as
#   outside (one lookup here, 203.0.113.8, which no host record carries, so it is not a victim); the manifest's
#   task counts follow, and it names the internal-network definition the hunt used.
#   Findings, citations, lanes, links and anchors are unchanged.
# A process-lineage link now places the anchor's own process by (time, audit serial), including the anchor's
# own record, and walks to its true parent: in the fixture, six lineage links select /bin/bash (the parent of the
# anchor's siblings) instead of a sibling chmod, so links, the context findings judged on them (claims, cited
# events, gate results), their context.finalize audit rows and the manifest change. Counts, lanes and anchors are
# unchanged; ordering the expansion budget by lane changes nothing in this fixture.
# The fixture's reverse-shell connect record carries its process's real parent and session, as the kernel
# records them (it carried pid - 1 and an unrelated session): its events, raw copies and the ids built from them
# change, and its login-session links go from a false complete over curl's session to unsupported (the shell has
# no login session), so the context cells judged on them are partial. host.persistence_path_change carries a new
# version for its serial-ordered package lineage. Lineage selections are unchanged; the queries those login-session
# fetches no longer spend let one capped source_ip link of the alert stack select more records (still partial).
# Anchors tied on lane, severity and time are ordered by their rule and evidence instead of their hunt-specific
# candidate id. Two of the fixture's anchors tie, so their links run in the other order: only which task fetched
# a raw record first (raw) and the order of the manifest's link accounting change; every link, anchor and finding
# is the same.
# The expansion summary records the budget it ran under (the fixture's fixed total of 180), and the report's
# expansion summary carries it with the queries spent: expansion, audit and manifest change by those fields only.
# The flow and session rules name the side that opened a connection only from a record that shows the opening, and
# cite the records that bound each interval they state. Seven of them carry new versions (rule_cells, candidates and
# manifest findings change by rule_version only), and net.outbound_volume_asymmetry's positive-only reason now names
# the connections it does not read as uploads, so the manifest's negative_claim for it changes. Its window cell
# stays positive_only and gains one informational reason (rule_cells only): the 301 connections that an Arkime SYN
# shows outside clients opened to the fixture's internal servers, with the 451,500 bytes the servers sent on them.
# Findings and citations are unchanged; the port-scan probes to db1 have no recorded opener and a server's port
# shape, but the internal side sent no data on them, so they are not named.
# Link fetches now persist only their final selected records, and task outcomes no longer duplicate selected event
# ids. The removed event, raw and event-entity rows were never cited by a finding, expansion link or coverage cell;
# retained normalized events and raw payloads are unchanged. Raw first_task_id now names the selecting link task
# instead of an earlier broad fetch task. No removed event introduced a unique entity, so the entity digest is stable.
# Audit SYSCALL groups that become no other typed event now become process_observed events, so the evidence version
# moved: every typed event id is rehashed and every event names the new normalizer, which changes every digest that
# carries an event id (events, event_entities, candidates, links, tasks, audit, manifest) and every normalized and
# pivot digest. The fixture writes no such group, so the events themselves are the same. With the old evidence version
# given the new number, the rest is: host.interpreter_external_connection and corr.process_network_link carry new
# versions (rule_cells, candidates, manifest); and both rules' bash connect finding gains the note why its lineage is
# unknown (its parent's exec is not in the window), with the network finding's claim stating it. The exec,
# file-change and observed records corr.process_network_link reads for lineage do not make a partition an evaluation
# of it, so its cells are otherwise unchanged. Lanes, anchors, links, raw copies and every other finding are unchanged.
# Suricata records whose sensor wrote no community id get the one computed from their 5-tuple, so the evidence version
# moved: every typed event id is rehashed and every event names the new normalizer, which changes every digest that
# carries an event id (events, event_entities, candidates, links, tasks, audit, manifest) and every normalized and
# pivot digest. The fixture's sensor writes a community id on every record, so with the old evidence version given the
# new number the normalized and pivot digests are the reference ones, and the rest is the change below.
# Claims state only what their citations carry. Aggregate claims cite the records that bound every span they state and
# a record for each value they name, say how many records are cited when they state more ("K of the N records are
# cited, including the first and the last"); the rules that do so carry new versions (rule_cells, candidates,
# manifest). In the fixture: the port scan, the protocol/port mismatches, beaconing, the alert stack, the tool user
# agent, the SSH login, the persistence change and both connect() rules change their claims; the port scan, the
# account change and both connect() rules cite more records (the scan's last flow record; the exec ancestors and
# observed records the lineage names); the alert stack's and the connect() rules' notes are reworded; the context
# items' "in this session" names the audit session or the anchor's lineage. Every candidate carries the ids it cites
# only for its claim's statements (context_event_ids), and expansion and the context pass start from its other records,
# so anchors, links, tasks, expansion and the context findings are those of the reference; the manifest's findings
# and incident graph follow the claims and citations, and the extra cited records add their events and raw copies.
# Every lane is unchanged.
# Each count a claim states is matched by how many of exactly that count are cited: the ten protocol/port mismatch
# findings that give per-sensor totals say how many of each sensor's records are cited, and the connect() link with
# one call says its one record is cited (candidates claims, and the manifest's findings that carry them). Candidate
# ids, citations, lanes and everything else are unchanged.
# The baseline stage runs after the sweep. This fixture has no pre-window history, so every baseline key is unresolved
# and no baseline candidate is published. It adds only baseline state: the baseline rule cells (window, history and
# rollup; the ids of later rule cells shift), the baseline task, the hunt.baseline_summary audit record, the manifest's
# baseline coverage block and task count, the baseline observations (which keep first-event source identities only)
# and the frozen snapshot. Candidates, events, event citations, entities, raw copies, anchors, links, expansion and
# stats are those of the reference.
# DNS client and server come from the DNS port, a process-network join cites a record of every sensor it names, a
# grouped write lead cites the files that bound its span, and a port scan says how many of its ports are cited: those
# rules carry new versions (rule_cells, candidates and the manifest's findings by rule_version). In the fixture only
# the port scan's claim changes (it gains "K of the N ports are in cited records"); its DNS records, joins and writes
# give the same roles and citations, so every other table is the reference's.
# The external-destination baseline keys DNS records by the DNS port's side (a question whose ports do not tell is
# read as sent), so bl.ext_dest carries version and key version 3. The fixture's DNS records give the same keys; the
# new versions change the snapshot plan and digest (the baseline snapshot, the hunt.baseline_summary audit record, the
# baseline task's id and outcome, and the snapshot_digest in every baseline rule cell and in the manifest's baseline
# coverage block), bl.ext_dest's rule cells by rule_version, and its 20 observations by spec_version and key identity.
# The hunt-derived writer publishes the complete window cells at finish, so segment/count/scope-hour and durable
# exclusion-ledger tables join the golden. Its summary changes only the baseline audit and report manifest.
# The fixture's finish now receives the baseline stage's summary, as a hunt's does. Its history is a failed gap, so
# the stage summary says the stage failed: the finish's hunt.baseline_summary record carries the stage summary beside
# the segment writer's, the hunt's stop reason names the baseline stage (its execution state was already partial),
# and the manifest's baseline coverage block reports the stage as partial instead of not run. The partial hunt writes
# no segment and keeps its window counter material.
# Registering bl.svc_exec_rate adds one unresolved www-data observation and its exact window-hour count on this
# no-history fixture. Baseline observations/window rows, the snapshot, exclusion ledger, rate rule cells, audit and
# report manifest change; findings, citations, evidence, entities, anchors, links, expansion and stats do not. The
# baseline task also changes by its rate spec in fingerprint, intent and outcome: retaining the old row would falsely
# say that the new spec did not run. Window scope-hour rows also retain a deterministic per-hour citation witness.
# The service-rate scope can now fall back to a typed system uid when process.user is absent, so its key version is 2.
# This fixture's named account produces the same semantic scope, but the versioned key id/digest changes its window
# count, observation and exclusion rows. The snapshot plan/digest changes, and that digest flows into baseline rule
# cells, the baseline task/audit summary and the manifest. Non-baseline candidates and all detection evidence remain
# byte-identical.
# Baseline S8 changes exec-pair and command-shape outcome/canonicalization semantics, external-destination DNS
# canonicalization, and the rate key's uid fallback. Their versioned identities change window counts, scope-hour
# witnesses, observations, exclusions, the frozen snapshot, baseline rule cells/task/audit and the manifest. Window
# count rows now identify their material hour, and exact event totals have their own captured table. DNS normalization
# now records the normalized DNS transaction id/version and uses UTS46 IDNA, so evidence version 12 rehashes every
# typed event id; candidates, links, tasks and their downstream audit/manifest references change by those identities.
# The fixture's non-baseline finding claims, lanes, citations and detector decisions are unchanged. Anchors, raw
# copies, entities, expansion, stats and the empty history/segment tables remain byte-identical.
GOLDEN_STACK = {
    "anchors": "0e89d2b2f2d7ccc701a87b49346c9894c84277b7cf8c725cc05d7d8449b88042",
    "audit": "4ac18411fc75aaea0724492e2bf0b79894c772bb7ec32987b6b7833098cbbf93",
    "baseline_counts": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "baseline_hunt_exclusions": "d3577183bfcf871f6712314c68522f64a01515a1e509d00925fcdca6eff143cf",
    "baseline_observations": "df05e88604c0ac3883a6c0ec9db5e3ff6e4e634068fc4d0bec785a1bbb794799",
    "baseline_scope_hours": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "baseline_segments": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "baseline_snapshot": "709fbd5828f6e5be380b34f2008f0b3937c4307ebcc33c4c16cdaa2267111068",
    "baseline_window_counts": "2a91438dfc4a6aa624de8256789a998f6453fc07f9511ff203edfba8ecfd518d",
    "baseline_window_event_hours": "d7ef5845a973ea1f92116e4c5660593b97316628436bf9ae58cf84af782d8ca4",
    "baseline_window_scope_hours": "b8b7eae859913f58f1fc355a778a3151c7082a1615bd63c6466a85b1ae87d89b",
    "candidates": "b5abecf132a0f5f4be6a541acb6a584f7b206821294991c5ae36ba89d2eb672b",
    "entities": "650d1be309f7d6fa2e86e6c1d2caffd582725898cea93a35d98214b6597be71b",
    "event_citations": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "event_entities": "9753e1bc55ffce6cfde297608596104c2ed3ef08cdd0a8db54e3ecb279fe392a",
    "events": "d4eede2cca8fd1bac673b1abe0aa2327cf7a5a3f90f72683680d2af986679e39",
    "expansion": "eec090afe70bb0c3e04e465bb014d8064b428e12dd256b3fe6aba14f4551acf6",
    "links": "e5bd8ec83459a57a14627ad2222f752e4c29e0415beddd54eaa11afd08e1b62f",
    "manifest": "fbfbe6c5f339ae46fd691ded3a29d3146abdfb0c996ce9e7e42a77b70327333d",
    "raw": "725a735679f5ca620ca5a4abf3145f7aef1ede27750a8b247e61c297ac02865a",
    "rule_cells": "17f4760cfde411877bac8e7762ce2555fa52a6aaeb5d2e48beb10b7ce677bafa",
    "stats": "bd8ad9ed18ba7ce308b269f12075a9e65cc877f4e023e23b1aa5f2279e571584",
    "tasks": "6de107dcab42d125ac48ea0aa135d46c74b431b216979513e4858afc85cbf580",
}
GOLDEN_NORMALIZED = {
    "arkime_sessions3-x": "49755f3034ebf83ec012716f283034f38087d5c7f1cabb0df5c1bf9a7db4eb10",
    "arkime_sessions3-x+boots": "49755f3034ebf83ec012716f283034f38087d5c7f1cabb0df5c1bf9a7db4eb10",
    "romulus-host-x": "7b698601e63b7c16fdb1c3b8bbf1cb1a28554bfa1ea19c2050dae704b8f7e6fa",
    "romulus-host-x+boots": "3f7e8e5acb3941e4aebd98d806854db6638826ae21aaf90e23c331b4c05a0a27",
    "romulus-network-x": "c7f6b8047e46c515a860217295c01d353fef49ca6e606475b79650eda20c3d3b",
    "romulus-network-x+boots": "c7f6b8047e46c515a860217295c01d353fef49ca6e606475b79650eda20c3d3b",
}
GOLDEN_PIVOT = {
    "arkime_sessions3-x:-": "1e222211f99bc0aa64458c9a629a263bdecd0a365eb28feb2d8bc2c8b1d52d18",
    "arkime_sessions3-x:process_exec": "1e222211f99bc0aa64458c9a629a263bdecd0a365eb28feb2d8bc2c8b1d52d18",
    "arkime_sessions3-x:net_socket": "1e222211f99bc0aa64458c9a629a263bdecd0a365eb28feb2d8bc2c8b1d52d18",
    "arkime_sessions3-x:auth,net_socket,process_exec": "1e222211f99bc0aa64458c9a629a263bdecd0a365eb28feb2d8bc2c8b1d52d18",
    "arkime_sessions3-x:net_flow": "1e222211f99bc0aa64458c9a629a263bdecd0a365eb28feb2d8bc2c8b1d52d18",
    "romulus-host-x:-": "198db87bdcf7ade9c2d53ea81bc15166c3e77734541da3fe82a925085c74ec33",
    "romulus-host-x:process_exec": "1837ef9198a0ab5552ea60ca415acc40be6cf9339fe7a5dafd51354e39f18ba0",
    "romulus-host-x:net_socket": "b92e4dc84c0403f132a2066b7cc32392f87cfa3d62bddeaa00e74e55ad9cea94",
    "romulus-host-x:auth,net_socket,process_exec": "198db87bdcf7ade9c2d53ea81bc15166c3e77734541da3fe82a925085c74ec33",
    "romulus-host-x:net_flow": "198db87bdcf7ade9c2d53ea81bc15166c3e77734541da3fe82a925085c74ec33",
    "romulus-network-x:-": "541211d1dc3e2ce1304804b4c9ca44842764853a3a43ecba3bce839906a62520",
    "romulus-network-x:process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_socket": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:auth,net_socket,process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_flow": "d87be864a0f1f1286442d5308c4621a727342cfff6ed3d280077adf034ac1d3b",
}
PIVOT_FAMILIES = (None, frozenset({"process_exec"}), frozenset({"net_socket"}),
                  frozenset({"process_exec", "net_socket", "auth"}), frozenset({"net_flow"}))


def _assert_every_citation_resolves_with_raw(snapshot):
    events = {row["id"]: row for row in snapshot["events"]}
    raw_ids = {row["id"] for row in snapshot["raw"]}
    citation_keys = {
        "event_id", "event_ids", "evidence_id", "evidence_ids", "first_event_id",
        "first_event_ids", "anchor_event_id", "anchor_event_ids",
    }
    cited = {
        event_id
        for row in [*snapshot["candidates"], *snapshot["links"]]
        for field in ("event_ids", "evidence_ids")
        for event_id in row.get(field) or []
    }

    def coverage_citations(value, key=""):
        if isinstance(value, dict):
            for name, nested in value.items():
                yield from coverage_citations(nested, name)
        elif isinstance(value, list):
            if key in citation_keys:
                yield from (item for item in value if isinstance(item, str))
            else:
                for nested in value:
                    yield from coverage_citations(nested, key)
        elif isinstance(value, str) and key in citation_keys:
            yield value

    cited.update(
        event_id for cell in snapshot["rule_cells"]
        for event_id in coverage_citations(cell.get("detail") or {})
    )
    assert cited
    assert cited <= set(events)
    assert all(events[event_id]["raw_ids"] for event_id in cited)
    assert {
        raw_id for event_id in cited for raw_id in events[event_id]["raw_ids"]
    } <= raw_ids


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _normalized(records, boots=None) -> dict:
    events, skips, errors = normalize_hits(records, boots)
    return {"events": [event.model_dump(mode="json") for event in events], "skips": skips, "errors": errors}


@pytest.fixture(scope="module")
def docs():
    return tf.build(1)


def test_the_sweep_and_expansion_stack_reproduces_the_captured_result(docs, tmp_path, monkeypatch):
    tf.patched_sizes(monkeypatch)
    snapshot = tf.run_stack(tmp_path, docs=docs)
    # the scenario is not vacuous: findings, splits, capped fetches, expansion links and a manifest
    assert {c["lane"] for c in snapshot["candidates"]} >= {"high", "lead"}
    assert sum(c["state"] == "split" for c in snapshot["rule_cells"]) > 100
    assert sum(t["state"] == "split" for t in snapshot["tasks"]) >= 2
    assert sum(link["status"] == "complete" for link in snapshot["links"]) > 10
    assert snapshot["manifest"]["findings"]
    _assert_every_citation_resolves_with_raw(snapshot)
    assert tf.digests(snapshot) == GOLDEN_STACK


def test_normalization_of_every_target_reproduces_the_captured_events(docs):
    got = {}
    for target, records in sorted(docs.items()):
        got[target] = _digest(_normalized(records))
        got[f"{target}+boots"] = _digest(_normalized(records, BootIntervals()))
    assert got == GOLDEN_NORMALIZED


def test_pivot_normalization_reproduces_the_captured_events(docs):
    executor = PivotExecutor(None, None, "h1", {})
    got = {}
    for target, records in sorted(docs.items()):
        for families in PIVOT_FAMILIES:
            events, errors = executor._normalize_pivot_records(records, set(families) if families else None)
            key = f"{target}:{','.join(sorted(families)) if families else '-'}"
            got[key] = _digest({"events": [e.model_dump(mode="json") for e in events], "errors": errors})
    assert got == GOLDEN_PIVOT
