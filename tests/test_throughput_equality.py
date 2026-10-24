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
GOLDEN_STACK = {
    "anchors": "0e89d2b2f2d7ccc701a87b49346c9894c84277b7cf8c725cc05d7d8449b88042",
    "audit": "9ff1e6bb2670cb97af97a418aac6138d53d986bd1f0f1746c846ab209ea7519f",
    "candidates": "85aa8b8e1a1c218be7c2cd434bbb0097d5aab3c380ce138ea63cb55de9271fcb",
    "entities": "650d1be309f7d6fa2e86e6c1d2caffd582725898cea93a35d98214b6597be71b",
    "event_citations": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "event_entities": "cf18bb6ae3e613d6cb411550ad8fa0e61c4070c55b24c85e174dcfe2add2841e",
    "events": "c9a4a79653fa4a88195d9f0126cc0c60a9b6eba2679d4c76a26abc514f560f80",
    "expansion": "eec090afe70bb0c3e04e465bb014d8064b428e12dd256b3fe6aba14f4551acf6",
    "links": "797137953f5a643e0297b450047aeec3fa79c4cb386118f10d0ec00d337fd023",
    "manifest": "c41454498ba57b14e4afa6f2b9502602141ee48132f83855bf236d934e9e6b06",
    "raw": "80a0409b9be30979db49d2050bf90b7a4ed6dd2014360e1a21151df3756d0329",
    "rule_cells": "84de97e40b40cbaed6ac7c42678577553b732e5c19a90a33db10501039fb34a9",
    "stats": "bd8ad9ed18ba7ce308b269f12075a9e65cc877f4e023e23b1aa5f2279e571584",
    "tasks": "5aea729f4d6dd201150516a14962f81c71d2035e3fa3518bc14ae685e76d0931",
}
GOLDEN_NORMALIZED = {
    "arkime_sessions3-x": "20b597e7169ff4713f006bd7b69608eea69a2038505dfa92fdf393709af2fe54",
    "arkime_sessions3-x+boots": "20b597e7169ff4713f006bd7b69608eea69a2038505dfa92fdf393709af2fe54",
    "romulus-host-x": "c8605640b20e6a43246db56f2367558b2fab33063ea7a56e4a17d3dcdbdcf9dd",
    "romulus-host-x+boots": "a21ec9b0aed076c9cee5436e392604732f4eb7cb0641045d538b7b9f2954a573",
    "romulus-network-x": "570f22b06412adcfad2fba2d17d71ebe4c28b40b1ae69dc89e5ed88325f03385",
    "romulus-network-x+boots": "570f22b06412adcfad2fba2d17d71ebe4c28b40b1ae69dc89e5ed88325f03385",
}
GOLDEN_PIVOT = {
    "arkime_sessions3-x:-": "10452ded995f9c13ed57ff9ff96c9fb3a859824f4ad87939ef5bdeefd2529b7a",
    "arkime_sessions3-x:process_exec": "10452ded995f9c13ed57ff9ff96c9fb3a859824f4ad87939ef5bdeefd2529b7a",
    "arkime_sessions3-x:net_socket": "10452ded995f9c13ed57ff9ff96c9fb3a859824f4ad87939ef5bdeefd2529b7a",
    "arkime_sessions3-x:auth,net_socket,process_exec": "10452ded995f9c13ed57ff9ff96c9fb3a859824f4ad87939ef5bdeefd2529b7a",
    "arkime_sessions3-x:net_flow": "10452ded995f9c13ed57ff9ff96c9fb3a859824f4ad87939ef5bdeefd2529b7a",
    "romulus-host-x:-": "b3b73239344c635784b888d698d2bcc9a7eeb816187500b97cbc2f1ab29ee7cb",
    "romulus-host-x:process_exec": "2342b20a28efdf4226f91bb8b4665857c585bbb865a9c055ecb9617bd394ac75",
    "romulus-host-x:net_socket": "e4ab66f60b9dc300f0a3e7426c4db6da78e95ebf6a0bbbd7eaff5684103b7ac8",
    "romulus-host-x:auth,net_socket,process_exec": "b3b73239344c635784b888d698d2bcc9a7eeb816187500b97cbc2f1ab29ee7cb",
    "romulus-host-x:net_flow": "b3b73239344c635784b888d698d2bcc9a7eeb816187500b97cbc2f1ab29ee7cb",
    "romulus-network-x:-": "1cd1a455435f582cb9214500155dd594e0fe845919c5f7607574d54039ba5c1e",
    "romulus-network-x:process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_socket": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:auth,net_socket,process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_flow": "6fbac86c1546e6f66cca0db257b23c5f0099622d61b3c2dfd46a9ad6240cd903",
}
PIVOT_FAMILIES = (None, frozenset({"process_exec"}), frozenset({"net_socket"}),
                  frozenset({"process_exec", "net_socket", "auth"}), frozenset({"net_flow"}))


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
