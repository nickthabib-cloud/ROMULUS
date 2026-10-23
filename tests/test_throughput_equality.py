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
GOLDEN_STACK = {
    "anchors": "0e89d2b2f2d7ccc701a87b49346c9894c84277b7cf8c725cc05d7d8449b88042",
    "audit": "538a65e82e05000f401b4dfa3288f0982b55c328e3cede607032141d0f81292d",
    "candidates": "2ad7bf7a7fb7a18555d594746745560c601f39317f8496653ac3bd21cb00a251",
    "entities": "650d1be309f7d6fa2e86e6c1d2caffd582725898cea93a35d98214b6597be71b",
    "event_entities": "af8053b6219447233c1329e280f0ca64054ceceeea79d5d84bfa12af8e067a23",
    "events": "d091e0a4b829e399e1011c9930f8a347a09b480ab7ca069361090e9ae1405c7c",
    "expansion": "eec090afe70bb0c3e04e465bb014d8064b428e12dd256b3fe6aba14f4551acf6",
    "links": "0c6ce53f0aa49c6f1e7aa63c0df576ecde37079b918cdce15183b8b30f946646",
    "manifest": "6e357bde832b9ef364f9e928e5c964ba9a23e845f6d2820c0b698cfffea06aa3",
    "raw": "03d2790712d2ac341c4dafcc4b89d7f991a025f637d97f7ef22cd33e35f4fbe0",
    "rule_cells": "7d7950159c1c13f9e7e023ce522ec2932005616c0f7fa89e9afe553d993ff57d",
    "stats": "bd8ad9ed18ba7ce308b269f12075a9e65cc877f4e023e23b1aa5f2279e571584",
    "tasks": "8547b413b445d75e25845cbc8ad6277db4e7bb5e9a18b0ed53bffb63b4df7b9b",
}
GOLDEN_NORMALIZED = {
    "arkime_sessions3-x": "ab962996ad3da493263e7cf5971b6d853a75684e82f9daff420d871ef389a1d0",
    "arkime_sessions3-x+boots": "ab962996ad3da493263e7cf5971b6d853a75684e82f9daff420d871ef389a1d0",
    "romulus-host-x": "a7e3ffc71f57ff338d00a3753240ee3be734858a60c7a1d853b35805161dc3fc",
    "romulus-host-x+boots": "b97f496b64e3ce3ddf7cdd877809f3a60422f7bc4e3966414bd606563010d2ab",
    "romulus-network-x": "3c1e45e5935924dd298d9a96d8b68f52b6645e27edd0d149177666eef8779b9c",
    "romulus-network-x+boots": "3c1e45e5935924dd298d9a96d8b68f52b6645e27edd0d149177666eef8779b9c",
}
GOLDEN_PIVOT = {
    "arkime_sessions3-x:-": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "arkime_sessions3-x:process_exec": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "arkime_sessions3-x:net_socket": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "arkime_sessions3-x:auth,net_socket,process_exec": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "arkime_sessions3-x:net_flow": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "romulus-host-x:-": "4afd3ecf807afb5ea259f5d026831276262c25d1d11de37ec29531e35fe6a7f2",
    "romulus-host-x:process_exec": "f7bf7581e1e98919cf7e9ea83db45b5c2d0e9120473bd5a5b17b68d568c433e2",
    "romulus-host-x:net_socket": "48af5566e02feae8fd9d8e0984ce9f769acbeb486061d7d4ec8668d8ccdea3a5",
    "romulus-host-x:auth,net_socket,process_exec": "4afd3ecf807afb5ea259f5d026831276262c25d1d11de37ec29531e35fe6a7f2",
    "romulus-host-x:net_flow": "4afd3ecf807afb5ea259f5d026831276262c25d1d11de37ec29531e35fe6a7f2",
    "romulus-network-x:-": "466c83ca2e7742088e31660fdcb82331bddd933e1e279ee63d3dbb71c98dab47",
    "romulus-network-x:process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_socket": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:auth,net_socket,process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_flow": "dfa383766f66b37d4c0f513001098b2ecbd15ad3320b48a7106f5ec19a52386d",
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
