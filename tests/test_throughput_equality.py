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
GOLDEN_STACK = {
    "anchors": "0e89d2b2f2d7ccc701a87b49346c9894c84277b7cf8c725cc05d7d8449b88042",
    "audit": "6af1b824ccfa0f6bc1332de83c7bcad95d53a08021cc76eb0cf347a3d47fea46",
    "candidates": "c70ac8e146d1356b64fc86eec38aa3a97352ea39d63390bfdd819b3cd4a7d8e8",
    "entities": "650d1be309f7d6fa2e86e6c1d2caffd582725898cea93a35d98214b6597be71b",
    "event_citations": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "event_entities": "02f54dc3284f6429932fa7c81f71d010cda2f72f5a9d69aaad35dae3f1bd1307",
    "events": "9ffd93186d36eda229ba0ed8ae404bebd9360221c888b3fe446f794f71963324",
    "expansion": "eec090afe70bb0c3e04e465bb014d8064b428e12dd256b3fe6aba14f4551acf6",
    "links": "a6a78b78aa676b98d84bc5498a164f20c23f1dcb20709a9a8dd6c0b11c5889ec",
    "manifest": "c56ea7fdbd662f111309569acfe8b4d6b685cfdda1727d95eba65bbaf872bb21",
    "raw": "28f646bc4a6964e8c8d1e9520bdc419947331053e0c778591039d72fb85c0ce8",
    "rule_cells": "5e54ecbffe6d72d614d4b6fd5798cc5eb5b95d6d1faceea83e75f357a49b9aed",
    "stats": "bd8ad9ed18ba7ce308b269f12075a9e65cc877f4e023e23b1aa5f2279e571584",
    "tasks": "cffcaf6466928eb0e6a228bbab1a902546d2fba2301ae8383eb03b133df2a4fc",
}
GOLDEN_NORMALIZED = {
    "arkime_sessions3-x": "06f98c12d69e05195c076fd782333b77fcaba75cf63afe11bc78a7f91100a93d",
    "arkime_sessions3-x+boots": "06f98c12d69e05195c076fd782333b77fcaba75cf63afe11bc78a7f91100a93d",
    "romulus-host-x": "2f63fecb4b594d2efae3c8d2fb3da44081ef4ee3c520511b70d5377d99a6d5af",
    "romulus-host-x+boots": "2091b790b25d60963635bf00478300ca29148e3df7969b2e767727e27bbaa5e2",
    "romulus-network-x": "1613a25e70c432b05d97032b1482c8f663e51454f4469d7792e79879a85ae4c0",
    "romulus-network-x+boots": "1613a25e70c432b05d97032b1482c8f663e51454f4469d7792e79879a85ae4c0",
}
GOLDEN_PIVOT = {
    "arkime_sessions3-x:-": "13ad382fd02400d2c2a752cec694e5e6ce84527ada5c33bb292ef6bfef64fd46",
    "arkime_sessions3-x:process_exec": "13ad382fd02400d2c2a752cec694e5e6ce84527ada5c33bb292ef6bfef64fd46",
    "arkime_sessions3-x:net_socket": "13ad382fd02400d2c2a752cec694e5e6ce84527ada5c33bb292ef6bfef64fd46",
    "arkime_sessions3-x:auth,net_socket,process_exec": "13ad382fd02400d2c2a752cec694e5e6ce84527ada5c33bb292ef6bfef64fd46",
    "arkime_sessions3-x:net_flow": "13ad382fd02400d2c2a752cec694e5e6ce84527ada5c33bb292ef6bfef64fd46",
    "romulus-host-x:-": "4381ac742cb9fb496eea6b93f780ee9a90dce4bcbba0a3809142b921e13157a6",
    "romulus-host-x:process_exec": "7db85d1a481d00d9ba8f69bf704fcb0bc3e861ff7f88915adf953b8c10864e2c",
    "romulus-host-x:net_socket": "fd4d94aa261284e2d89eb1913fe664eb8689813cbb047e31727a0313aa081f5f",
    "romulus-host-x:auth,net_socket,process_exec": "4381ac742cb9fb496eea6b93f780ee9a90dce4bcbba0a3809142b921e13157a6",
    "romulus-host-x:net_flow": "4381ac742cb9fb496eea6b93f780ee9a90dce4bcbba0a3809142b921e13157a6",
    "romulus-network-x:-": "26602db2ee376909da616138fb9cabb09717a2d4c0dcff3962d102d735d6b408",
    "romulus-network-x:process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_socket": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:auth,net_socket,process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_flow": "1cb749978530f8fdc3306a3032f00880594c2aa2bd82157f611c96f394b19a53",
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
