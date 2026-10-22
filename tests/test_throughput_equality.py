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

# Reference digests of the synthetic fixture's results; any change to hunt output changes them.
# Re-recorded when detector state moved to disk-backed stores: candidates, rule_cells and manifest changed only
# because rule versions were bumped. With each rule's version set back to its previous value, every digest matched
# the earlier reference.
GOLDEN_STACK = {
    "anchors": "5bfad42385ad92785c91d770613dff8e893f140c4f8d1606128b7ea0f170c120",
    "audit": "2fd12fa42a64f8c3bb7a8079c056f68e24d4c371b69644eaf02688e6c706ab6a",
    "candidates": "20ce186d033f7990348a800b46bc5a3091f07d2f491bf0bdbfc94dc1b9f76a6f",
    "entities": "650d1be309f7d6fa2e86e6c1d2caffd582725898cea93a35d98214b6597be71b",
    "event_entities": "af8053b6219447233c1329e280f0ca64054ceceeea79d5d84bfa12af8e067a23",
    "events": "7cb68efe39e15155efa9b2f8edc22e79b93fb3804ba23981e97fbde26c5b0664",
    "expansion": "5a12fe7c7f06127db41f5229bda524a0c9e21e101f8d87dc32d10e5589358770",
    "links": "c6589f2bef67ee2bab7f194cb3fa551ff913ac43266ce8cd6a20efd2d6c0aa2b",
    "manifest": "2d694cbcdc075afbc68d33b9dd952827daca0e68d6f52f061793cdb7d0c08b4b",
    "raw": "f3c3185ebf52b2b84224ea7866648e6bbe117267a423b600f203d780178efad9",
    "rule_cells": "e8032e37b0afe44f6a250fc798d39b6be764f4e928f4e252f8ac5b9082f5b1cd",
    "stats": "bd8ad9ed18ba7ce308b269f12075a9e65cc877f4e023e23b1aa5f2279e571584",
    "tasks": "a6118de2aa8b88a5f50f08d3476de4e866c6dd69e4f4a49407e98f06198ee497",
}
GOLDEN_NORMALIZED = {
    "arkime_sessions3-x": "ab962996ad3da493263e7cf5971b6d853a75684e82f9daff420d871ef389a1d0",
    "arkime_sessions3-x+boots": "ab962996ad3da493263e7cf5971b6d853a75684e82f9daff420d871ef389a1d0",
    "romulus-host-x": "60bbbaa88c39eb7c697999a8dedce742d6dc50de5a124d3dca875afa4e7ddd68",
    "romulus-host-x+boots": "38fa3a3f4a40d5715b7d991390267fcc102d9d24c212f0610cad8ec9edd9da56",
    "romulus-network-x": "3c1e45e5935924dd298d9a96d8b68f52b6645e27edd0d149177666eef8779b9c",
    "romulus-network-x+boots": "3c1e45e5935924dd298d9a96d8b68f52b6645e27edd0d149177666eef8779b9c",
}
GOLDEN_PIVOT = {
    "arkime_sessions3-x:-": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "arkime_sessions3-x:process_exec": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "arkime_sessions3-x:net_socket": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "arkime_sessions3-x:auth,net_socket,process_exec": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "arkime_sessions3-x:net_flow": "91ce87f37ed5f17a44662406c7c6008266e67a66b045a099016c014b8d4253e7",
    "romulus-host-x:-": "4c5fec229946fc8bdeb26604fa48b1b56ddf545f6afa38e6db12d4aa3131ec47",
    "romulus-host-x:process_exec": "f7bf7581e1e98919cf7e9ea83db45b5c2d0e9120473bd5a5b17b68d568c433e2",
    "romulus-host-x:net_socket": "a8cc9fcf3a6dfb3628515478683b790cda27992b6cd4758945d3cdaac9f88a28",
    "romulus-host-x:auth,net_socket,process_exec": "4c5fec229946fc8bdeb26604fa48b1b56ddf545f6afa38e6db12d4aa3131ec47",
    "romulus-host-x:net_flow": "4c5fec229946fc8bdeb26604fa48b1b56ddf545f6afa38e6db12d4aa3131ec47",
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
