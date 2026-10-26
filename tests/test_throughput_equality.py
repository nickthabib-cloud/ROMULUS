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
# Evidence version 13 strictly types Suricata TCP/ICMP, Arkime ICMP and Zeek ICMP conn fields. The fixture has no
# qualifying ICMP echo transfer, so the new rule adds coverage cells but no candidate; its raw records remain
# byte-identical. Rehashed typed-event identities change their dependent rows. The Suricata opener correction changes
# only the affected rules' versions in this fixture: the field-level projection confirms candidate claims, lanes,
# priorities, citations and gates are unchanged, while rule-cell count/fields include the new ICMP evaluator.
# Observation-aware lineage adds source-backed process observations as context citations to the fixture's affected
# auth/tamper, persistence and reverse-shell findings; candidate event_records/context_event_records and those rules'
# versions change. Claims, lanes, priorities, predicates, gates, group keys and candidate count remain identical.
# The same version bumps change rule_cells only in rule_version; evaluated/matched/state/detail and cell count are
# identical. Expansion selects the same records in this fixture, and raw source records remain byte-identical.
# Incident grouping labels observed expansion links as evidence and all inferred links as hypotheses. Only observed
# links join components; inferred links stay visible between incidents. This changes only the manifest's incident
# projection in the fixture: candidates, links, lanes, claims, citations, rule cells and raw source records remain
# byte-identical.
# Evidence version 14 accepts Arkime's real multi-valued ICMP fields and treats Zeek's responder port as the
# counterpart type rather than an ICMP code. The fixture has no Zeek records and no qualifying ICMP finding, so the
# normalized event content changes only by producer/version identity. That rehashes typed-event references in the
# event, entity, candidate, link, baseline observation/scope-hour and report rows; raw source records are
# byte-identical. The ICMP, process-network and interpreter-connect rule versions change rule cells and candidate
# version fields only: the field-level projections below prove the 35 claims, lanes, priorities, cited raw records,
# gates and all other machine decisions are unchanged. Observed-only incident joining restores the exact a136ed2
# incident membership while retaining inferred links as labelled hypotheses in the manifest.
# The round-three corrections move host.persistence_path_change to version 8 (package attribution now accepts only
# exact system-path package-manager images) and net.icmp_echo_tunnel_shape to version 3 (high requires comparable
# two-sided counters; mixed/nonstandard codes and one-sided records are worded rather than hidden or overstated).
# This fixture has no qualifying ICMP candidate, and its persistence result has the same grouping, claim and lane.
# Candidate and rule-cell field projections change only in rule_version; the manifest follows that candidate version.
# Every raw source record, citation, decision, lane, claim, gate, link, incident and other stack digest is identical.
# The hunt-derived writer now decides per (target, spec, hour) from that hour's own window cells, so this hunt, partial
# for reasons outside the baseline, writes the whole hours whose cells are complete:
# - baseline_segments, baseline_counts, baseline_scope_hours: 14 hunt-derived segments of the 13:00-15:00 span for the
#   five specs and targets that allow it (bl.ext_dest is refused: the fixture's internal networks are the default;
#   the host target's exec-pair cut is refused for its unresolvable cited child); each carries events_basis 2 and
#   its first_event_hour. Segments of targets that deliver none of a spec's records are empty.
# - audit: the hunt.baseline_summary segment_writer per-spec reasons name the hours not written ("1 hour(s) not
#   written: an incomplete window cell") instead of "hunt is partial", with counts written, and a material block (kept
#   for a resume, its estimated bytes, the disk budget). The writer's measured write-lock time is wall clock, so the
#   fixture now drops max_write_seconds like its other wall-clock fields.
# - baseline_observations: every scope is unresolved by its spec's own history coverage, so the judge no longer
#   probes history and prevalence for them: history_count, n_hours, peer_scopes and peer_scopes_with_key go from 0
#   (probed over no history) to null (not assessed). Verdicts and reasons are unchanged.
# The window counter material stays (the partial hunt keeps it for one resume), so the window tables are unchanged.
# Candidates, rule cells, links, tasks, events and the manifest are unchanged.
# Review corrections then change baseline fields only:
# - rule_cells: the 121 not_applicable_no_events window cells of the baseline specs record retrieval_complete (true
#   here), so an inapplicable target's empty cell from a partial retrieval is never written as complete history.
# - baseline_segments: rows_digest now also covers each segment's per-hour event totals (the new
#   baseline_segment_event_hour rows that place a straddling segment's first in-plan record).
# - audit: the segment writer's material block states over_budget (false).
# Combined with evidence version 14, baseline observation and scope-hour witness event identities retain the carried
# branch's rehashed values, and the audit summary follows those rows. Rule cells combine S9's retrieval_complete
# details with the persistence/ICMP rule versions above; the non-baseline field projection remains byte-identical.
# Deduplicated window material then keeps each key's dedup token per hour, so hunts write external-destination
# history from network cells of any width:
# - baseline_window_counts: every row gains a token column ("" for the 885 rows of keys counted per record, which
#   are otherwise unchanged); the 76 bl.ext_dest rows become 234 rows, one per (key, hour, token) seen in a cell,
#   including tokens the cell's open-bucket set suppressed.
# - audit: the material block's estimated bytes follow (807,272 -> 921,326), and the retention reason says what
#   releases kept material ("kept while the hunt can still resume; released at its resumed finish, or by the disk
#   budget, oldest first").
# Merged with the carried detection bundle (evidence version 14, pack 32): against that tree only the two baseline
# fields above differ (baseline_window_counts and the audit's material bytes and retention reason); every other
# digest and the non-baseline semantic projection equal it exactly.
GOLDEN_STACK = {
    "anchors": "0e89d2b2f2d7ccc701a87b49346c9894c84277b7cf8c725cc05d7d8449b88042",
    "audit": "614446dde4d3c43898b348d80f33a9f16fea73296f3902c17d0d4ca5f9a8b1ad",
    "baseline_counts": "1a021de3254f91225689f1bdc8ce3e0cfd416c90a4148bcd4f1c93b6db9cb16d",
    "baseline_hunt_exclusions": "fe9edaf9efe3065352ae1bedc95ac7e78ddbe2d6e34f835203cfe56cb368ec56",
    "baseline_observations": "b25abf252a28151beae7d2048372e8be9dcafc76622b1a5f79ca1fd85a597784",
    "baseline_scope_hours": "fe1ef875f82a6cad7d9c7884b1936614584a9f9e0e4c008e4790ee46edf6361d",
    "baseline_segments": "e2ca9f003a97f77ac300789266c9e646610317f5577318c4b556b464a8a6fc48",
    "baseline_snapshot": "63b4c8094cb5450b1e707fd7be786e90324528e738b882358cae15cb8d53f776",
    "baseline_window_counts": "425d3bd3047505695a79b62d375e007bdbc41eb0a840e856fbac4871c5a622e5",
    "baseline_window_event_hours": "bb58c65144b135443e75a690b7b2f8137ebac6b827f8e8bd8cc7606a01c53e52",
    "baseline_window_scope_hours": "e3a243191b5431410f587f279c22b2f949717be2c5e5a228e43d4893caf2965f",
    "candidates": "3b23f98dbf25d34c4921bbec2cba932991746ad9d4a11e8963988d7c8c421bee",
    "entities": "650d1be309f7d6fa2e86e6c1d2caffd582725898cea93a35d98214b6597be71b",
    "event_citations": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "event_entities": "40eefa75e2cfa03734adb2e57b3da8719aa150bcdc65e72a758d84ba3e1f31b7",
    "events": "0165d2807ffee33aaef17dd70ba004ec4c87fa4c5f29e9dc75ba833f57b93ff7",
    "expansion": "eec090afe70bb0c3e04e465bb014d8064b428e12dd256b3fe6aba14f4551acf6",
    "links": "0fbedb27ca9a4cb72354178444ee9aabc49f377b2c933074fe03ef29c8fbb08a",
    "manifest": "e7f0f06c2bf744a08516f7b254454c3f5e517498d7275d9e80e85f5760a521f4",
    "raw": "725a735679f5ca620ca5a4abf3145f7aef1ede27750a8b247e61c297ac02865a",
    "rule_cells": "e1bc4bf141c508b8ca70ab69d34b64edc50b19112dd4d1d901623b41e42cf871",
    "stats": "bd8ad9ed18ba7ce308b269f12075a9e65cc877f4e023e23b1aa5f2279e571584",
    "tasks": "f0c05a2a05135e822ab077a843472e4cb4d31b93b5c27050685bf6b9675e4cdc",
}
# Captured directly from the S7 fixture through _non_baseline_semantic_digests. Typed-event-derived hashes and
# interchangeable predicate origins are normalized, while every decision, claim, lane, raw citation and gate is
# checked field by field.
GOLDEN_NON_BASELINE_SEMANTICS = {
    "candidates": {
        "all_fields": "7b24cd315e4dd449433731f2405ada13616b0e1c647bb3c4bdd98e3ff4293e24",
        "benign_alternatives": "8e3c0bf9bd14733cc2b4a049393aded638eaa0e93632c2c69d1428a52a4cc221",
        "claim": "94f373eede1b0deee042a316fc9ede39a619bbef58ded217ad94860f9fd4a2b0",
        "claim_type": "1ccc0da03751218f3bb63463a348cd5519fb63c2eec9e0d2e83259f18bfc6681",
        "confidence": "307872061aea17d3b0ed62d34865ad350c9b4cb9cc7d2cea041ca39011ee3e7e",
        "context_event_records": "af444f5420b16faa27b03fe9091a6b2db5006bcc5da813d573f7a01c97490121",
        "count": 35,
        "entities": "dfb7f8d1a995807f75365452dae6c80e325d1f2d1ad42f1fd1a2bb1292b98d21",
        "event_records": "20e95e203b846d9ee194e97d157589d48720f22fd8ec7dad3c7875d31d307104",
        "gate_results": "1494f3c1cd4853709e0ccaa599c397076f29a9b8ef2431c339d607cabb57f46e",
        "group_key": "e568af201841df36a89a8f8cebf9384f4fae5219b5fa742761a17778c24e21db",
        "lane": "2a992b1fbb25d9d7cddc90e6ada69d30c0eb0e743881c35e567bd8cc08828f3b",
        "next_checks": "a8069762d98e73840e159485c7fd877c5bc891cb9eab67f139c75af1e1eb979f",
        "predicate_fields": "578a1d5b70a2fcc8a4cb62c5c02ceb1bdae66cd8c85400a4da6412aa77b70c16",
        "priority": "aa73edc71e40ea4964645f62817edb7b3e790121d824db413442d99a21c05d5d",
        "priority_reasons": "b473ae5921bb2f50e3cc347ad18a3a5b6557ecacdaca7568e9f2f10b2fde3a9b",
        "rule_id": "2ae926e61da026e299be84e4e716e9bd0a33eb9a6ea3c97196c3167fc017a257",
        "rule_version": "cbca529ae2a2cea47a87d3595513d4d4fe63a44b80760ade9050ec23392a1647",
        "severity": "b2e229e267531f35a076f4db58edc48cbea38cce613ae2a6954cb6b1bf5ea20c",
        "source_presence": "4b20d257ae462d3a6c1af7eeddf340a1558a100d29f517eb7b5c7564fa778d1c",
        "ts": "d8015c1ff0b135e082a5fef2ab1cb88206470e30beee157a0cfc7790d48b8310",
    },
    "rule_cells": {
        "all_fields": "5286716472ed525e78dd5eaabb70782b0325bd81fe37a7d87a96ac1a35b6107a",
        "count": 3759,
        "detail": "7dad162b4173d4b9f014717ab13d87382aded61790606b387cece6938b9b9798",
        "evaluated": "6f10cc3cc36af740c1a133d78b648916a0d0a463f51db238b4e4e15aad2ea62e",
        "matched": "1460c4f475a6c0a48415daab1be5e03906b62e10569c6b35c5e4398d35c72d0a",
        "partition": "6d893f4a6e8876b97fa5839af1065eb368ecd4008b4dc62d1692ba7a5bcf5f5a",
        "rule_id": "1712462d1ecbce33955ffb2201e0c99d313a625ffd4fa9126d74bb4f885167e4",
        "rule_version": "43077c7fcb092249a2880c625ca4629f0b173fd887988695ed54dae1542b9d5c",
        "state": "fac91f9282f733342d72de53553d08230fea025fe7a9e51904f5fb38d82da182",
        "target": "70109432b9c54dfed31dfefde5a7ab6e6f5e0dd28262f395027792e6c7d5ad96",
    },
}
GOLDEN_NORMALIZED = {
    "arkime_sessions3-x": "76c065038118637c891297b82047c3ea0fcb2ace74b102729e0fe80275ae33fa",
    "arkime_sessions3-x+boots": "76c065038118637c891297b82047c3ea0fcb2ace74b102729e0fe80275ae33fa",
    "romulus-host-x": "5fe0efe8dac7c2dffe71402412ef3f79634364cc52ec7fd3286b9ba0c9fe6443",
    "romulus-host-x+boots": "e1258e86ff0b5db0e5421836711f85d344b8190844d0a4957d28931c5c5f13b2",
    "romulus-network-x": "28e79f5b436bae5a0b37351fecd103a5433efac7388ef78496f40d2138843894",
    "romulus-network-x+boots": "28e79f5b436bae5a0b37351fecd103a5433efac7388ef78496f40d2138843894",
}
GOLDEN_PIVOT = {
    "arkime_sessions3-x:-": "63667fe3f7a1d8a043aeb6f4c90dd81d5b95d9bc09615509d7509930f781b521",
    "arkime_sessions3-x:process_exec": "63667fe3f7a1d8a043aeb6f4c90dd81d5b95d9bc09615509d7509930f781b521",
    "arkime_sessions3-x:net_socket": "63667fe3f7a1d8a043aeb6f4c90dd81d5b95d9bc09615509d7509930f781b521",
    "arkime_sessions3-x:auth,net_socket,process_exec": "63667fe3f7a1d8a043aeb6f4c90dd81d5b95d9bc09615509d7509930f781b521",
    "arkime_sessions3-x:net_flow": "63667fe3f7a1d8a043aeb6f4c90dd81d5b95d9bc09615509d7509930f781b521",
    "romulus-host-x:-": "17e03394f575dd068d9e6f86855ddbeb51bb4afadd8847d5607c02d3cba6f5af",
    "romulus-host-x:process_exec": "d406164da63f1e9b16c179688f7ceeb02c4c32d3951315607e5b6cee439d2b61",
    "romulus-host-x:net_socket": "6fda3c49eb2e715cddd5b54056fc42b79207fe02cc86232107d248895a9604e7",
    "romulus-host-x:auth,net_socket,process_exec": "17e03394f575dd068d9e6f86855ddbeb51bb4afadd8847d5607c02d3cba6f5af",
    "romulus-host-x:net_flow": "17e03394f575dd068d9e6f86855ddbeb51bb4afadd8847d5607c02d3cba6f5af",
    "romulus-network-x:-": "227b695914720fcbcaf7aa096fbbe8bae060ed5c4d53cf10bb25b64fb446a634",
    "romulus-network-x:process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_socket": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:auth,net_socket,process_exec": "9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6",
    "romulus-network-x:net_flow": "6968b431c3b39aa5ac7bcbe63082d96b23caf5ffa859bfcfd73e1db007783917",
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
