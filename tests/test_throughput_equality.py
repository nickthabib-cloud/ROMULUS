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
import re

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
# Expansion link accounting is now content-sorted before the raw manifest is emitted, so only the manifest digest
# changes; the links themselves and their canonical report order are unchanged.
# The S8 merge-gate correction moves bl.cmd_shape to version/key version 3. Path-shaped argv tokens now remain
# literal, while only evidenced Base64 and known random tmp/temp basenames are masked. That deliberate baseline-only
# identity change updates command-shape keys and version fields in window counts, witnesses, observations and
# exclusions; the frozen plan/digest then flows into baseline rule cells, the baseline task/audit and the manifest.
# Exact non-baseline candidate and rule-cell field projections remain equal to their S7 references below.
# The second merge-gate correction moves bl.cmd_shape to version/key version 4. Evidenced Base64 may contain `/`,
# and mktemp's mixed-case or `tmp.` random suffixes are masked without changing path-shaped or word-like names.
# The fixture's command shapes are unchanged, so only versioned command-shape identities, their baseline rows and
# the snapshot-derived baseline cells/task/audit/manifest change; non-baseline semantic projections stay identical.
GOLDEN_STACK = {
    "anchors": "0e89d2b2f2d7ccc701a87b49346c9894c84277b7cf8c725cc05d7d8449b88042",
    "audit": "d48d2621f6db2d9fc504f613ece9fb036cc20bc53b22cc0a5c128f9076288973",
    "baseline_counts": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "baseline_hunt_exclusions": "fe9edaf9efe3065352ae1bedc95ac7e78ddbe2d6e34f835203cfe56cb368ec56",
    "baseline_observations": "629be8768a4e8e673f7145d30e61da1e157d0898f079c6d9ee41eb744cce861a",
    "baseline_scope_hours": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "baseline_segments": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "baseline_snapshot": "63b4c8094cb5450b1e707fd7be786e90324528e738b882358cae15cb8d53f776",
    "baseline_window_counts": "163b75766bc7cc487118b4e8bc24fe338d9e364898f9200887b89ba11b464acc",
    "baseline_window_event_hours": "bb58c65144b135443e75a690b7b2f8137ebac6b827f8e8bd8cc7606a01c53e52",
    "baseline_window_scope_hours": "49a7182642abe3b848eb33b97e628395e57d806d9feeeaa8b9b198f0c07489d8",
    "candidates": "b5abecf132a0f5f4be6a541acb6a584f7b206821294991c5ae36ba89d2eb672b",
    "entities": "650d1be309f7d6fa2e86e6c1d2caffd582725898cea93a35d98214b6597be71b",
    "event_citations": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "event_entities": "9753e1bc55ffce6cfde297608596104c2ed3ef08cdd0a8db54e3ecb279fe392a",
    "events": "d4eede2cca8fd1bac673b1abe0aa2327cf7a5a3f90f72683680d2af986679e39",
    "expansion": "eec090afe70bb0c3e04e465bb014d8064b428e12dd256b3fe6aba14f4551acf6",
    "links": "e5bd8ec83459a57a14627ad2222f752e4c29e0415beddd54eaa11afd08e1b62f",
    "manifest": "04a003a9c55a069ee63954c0f7540fa4cc0bf91ca0e5570f120da48cffe91e61",
    "raw": "725a735679f5ca620ca5a4abf3145f7aef1ede27750a8b247e61c297ac02865a",
    "rule_cells": "04cb50a84ef9c5f9edfc3e5983e9a9eea13e69a1ce19c462fb1af4f48face93e",
    "stats": "bd8ad9ed18ba7ce308b269f12075a9e65cc877f4e023e23b1aa5f2279e571584",
    "tasks": "f0c05a2a05135e822ab077a843472e4cb4d31b93b5c27050685bf6b9675e4cdc",
}
# Captured directly from the S7 fixture through _non_baseline_semantic_digests. Typed-event-derived hashes and
# interchangeable predicate origins are normalized, while every decision, claim, lane, raw citation and gate is
# checked field by field.
GOLDEN_NON_BASELINE_SEMANTICS = {
    "candidates": {
        "all_fields": "1449f2eda5df5db8bba1f2953ecf743590fbccb5827ae924c4d7ff911e6370cc",
        "benign_alternatives": "8e3c0bf9bd14733cc2b4a049393aded638eaa0e93632c2c69d1428a52a4cc221",
        "claim": "94f373eede1b0deee042a316fc9ede39a619bbef58ded217ad94860f9fd4a2b0",
        "claim_type": "1ccc0da03751218f3bb63463a348cd5519fb63c2eec9e0d2e83259f18bfc6681",
        "confidence": "307872061aea17d3b0ed62d34865ad350c9b4cb9cc7d2cea041ca39011ee3e7e",
        "context_event_records": "14e8dd60caac665ccc2c9570d79e5556b3cd929f6d77e471ee65e0ced5529799",
        "count": 35,
        "entities": "dfb7f8d1a995807f75365452dae6c80e325d1f2d1ad42f1fd1a2bb1292b98d21",
        "event_records": "d1e3c446a09e2c4921cc3562b4cfa20f9be678868ba2976a65cd049fdabbae48",
        "gate_results": "1494f3c1cd4853709e0ccaa599c397076f29a9b8ef2431c339d607cabb57f46e",
        "group_key": "e568af201841df36a89a8f8cebf9384f4fae5219b5fa742761a17778c24e21db",
        "lane": "2a992b1fbb25d9d7cddc90e6ada69d30c0eb0e743881c35e567bd8cc08828f3b",
        "next_checks": "a8069762d98e73840e159485c7fd877c5bc891cb9eab67f139c75af1e1eb979f",
        "predicate_fields": "578a1d5b70a2fcc8a4cb62c5c02ceb1bdae66cd8c85400a4da6412aa77b70c16",
        "priority": "aa73edc71e40ea4964645f62817edb7b3e790121d824db413442d99a21c05d5d",
        "priority_reasons": "b473ae5921bb2f50e3cc347ad18a3a5b6557ecacdaca7568e9f2f10b2fde3a9b",
        "rule_id": "2ae926e61da026e299be84e4e716e9bd0a33eb9a6ea3c97196c3167fc017a257",
        "rule_version": "2142bc3ed67292746dfe53ca60a03a13e3c92a2cffc7b02f5a9dbec3f551101f",
        "severity": "b2e229e267531f35a076f4db58edc48cbea38cce613ae2a6954cb6b1bf5ea20c",
        "source_presence": "4b20d257ae462d3a6c1af7eeddf340a1558a100d29f517eb7b5c7564fa778d1c",
        "ts": "d8015c1ff0b135e082a5fef2ab1cb88206470e30beee157a0cfc7790d48b8310",
    },
    "rule_cells": {
        "all_fields": "8e74a064318014defdc8084d3f44c5e64e91f002cd85268146431a9e0bb88f68",
        "count": 3688,
        "detail": "3b6af381df806efdc5499095d6bdada58f46a51ad0fe49ef73b7943cf00bd1f7",
        "evaluated": "9a4cc79e7039a5e5987bfa7865f4e6e792c5b79bc164e5b8d12dd1a0ebfc790a",
        "matched": "5f86646f1c45362a125a457db638a1bc775450b07628b809bd008c3fd15ee45f",
        "partition": "b172589e7b406a22e7325bd06a8df239958a812c681c846dc588734b82a04807",
        "rule_id": "10210f59a0598c51c024391f3880dea1cbbb8b9edb7d9d0236b06f3e2571934c",
        "rule_version": "4fc681e6e7ff900d86bf15f7eb989457a3daefbcf56649989fae0f1597dd0390",
        "state": "58b1b96d6f59540c4b4a12550f3aeca9bd5751269e49d4909a1899443f169442",
        "target": "ab5599793d6b17b874ecfbb346dcffe738e30bcd85366dadcae28ac17c8e2545",
    },
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


def _raw_event_identity(event_id, events):
    event = events[event_id]
    return sorted(event["raw_ids"])


def _normalize_detail_citations(value, events, key=""):
    citation_keys = {
        "event_id", "event_ids", "evidence_id", "evidence_ids", "first_event_id",
        "first_event_ids", "anchor_event_id", "anchor_event_ids",
    }
    if isinstance(value, dict):
        return {name: _normalize_detail_citations(nested, events, name) for name, nested in value.items()}
    if isinstance(value, list):
        if key in citation_keys:
            return sorted(_raw_event_identity(item, events) for item in value)
        return [_normalize_detail_citations(item, events, key) for item in value]
    if isinstance(value, str) and key in citation_keys:
        return _raw_event_identity(value, events)
    return value


def _field_digests(rows, fields):
    def ordered(values):
        return sorted(values, key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))

    return {
        "all_fields": _digest(rows),
        "count": len(rows),
        **{field: _digest(ordered([row[field] for row in rows])) for field in fields},
    }


def _semantic_group_key(value):
    return re.sub(r"(?<=\|lin:)[0-9a-f]+", "<typed-event-identity>", value)


def _semantic_gate_results(value):
    result = {key: nested for key, nested in value.items() if key != "_finalize_digest"}
    if "_context_reaches" in result:
        result["_context_reaches"] = sorted(
            ({"link_type": row["link_type"], "strength": row["strength"]} for row in result["_context_reaches"]),
            key=lambda row: (row["link_type"], row["strength"]),
        )
    return result


def _non_baseline_semantic_digests(snapshot):
    events = {row["id"]: row for row in snapshot["events"]}
    candidates = []
    for row in snapshot["candidates"]:
        if row["rule_id"].startswith("bl."):
            continue
        candidates.append({
            "rule_id": row["rule_id"],
            "rule_version": row["rule_version"],
            "ts": row["ts"],
            "claim": row["claim"],
            "claim_type": row["claim_type"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "lane": row["lane"],
            "priority": row["priority"],
            "priority_reasons": row["priority_reasons"],
            # Exact cited raw records are compared separately. Predicate origins may select a different one of
            # two cited records that carry the same value when typed-event ids are rehashed.
            "predicate_fields": [
                {"field": item["field"], "value": item["value"]} for item in row["predicate_fields"]
            ],
            "entities": row["entities"],
            # Context grouping/finalization hashes contain typed-event ids. Preserve their semantic shape and
            # every gate outcome while excluding those derived identities.
            "group_key": _semantic_group_key(row["group_key"]),
            "gate_results": _semantic_gate_results(row["gate_results"]),
            "benign_alternatives": row["benign_alternatives"],
            "next_checks": row["next_checks"],
            "event_records": sorted(_raw_event_identity(item, events) for item in (row["event_ids"] or [])),
            "context_event_records": sorted(
                _raw_event_identity(item, events) for item in (row["context_event_ids"] or [])
            ),
            "source_presence": {
                "anchor": row["source_anchor_id"] is not None,
                "case": row["source_case_id"] is not None,
                "link": row["source_link_id"] is not None,
            },
        })
    candidates.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":"), default=str))

    rule_cells = [{
        "rule_id": row["rule_id"],
        "rule_version": row["rule_version"],
        "target": row["target"],
        "partition": row["partition"],
        "state": row["state"],
        "matched": row["matched"],
        "evaluated": row["evaluated"],
        "detail": _normalize_detail_citations(row["detail"], events),
    } for row in snapshot["rule_cells"] if not row["rule_id"].startswith("bl.")]
    rule_cells.sort(key=lambda row: (
        row["rule_id"], row["rule_version"], row["target"], row["partition"],
    ))
    return {
        "candidates": _field_digests(candidates, tuple(candidates[0])),
        "rule_cells": _field_digests(rule_cells, tuple(rule_cells[0])),
    }


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
    assert _non_baseline_semantic_digests(snapshot) == GOLDEN_NON_BASELINE_SEMANTICS


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
