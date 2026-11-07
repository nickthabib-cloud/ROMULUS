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
# the connections it does not read as uploads, so the manifest's per-rule coverage text for it changes. Its window cell
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
# Kept carry input is bounded by a retention horizon and a disk budget: the baseline stage summary's lookback block
# states the hours each removed (carry_hours_pruned and carry_hours_trimmed, 0 here), in the hunt.baseline_summary
# audit records and the baseline task's outcome; nothing else changes.
# An exec or process image of unrecorded boot is now a break for its host (it may be a pid reuse in the current
# boot), never stored or silently superseded, and dedup tokens are kept only for hours a cell shares with others:
# - rule_cells, manifest coverage gaps: 22 bl.exec_pair window cells' unresolved reasons for children whose lineage
#   crosses such a record read "an exec of the host between parent and child was not carried" instead of "parent exec
#   in an unobserved hour", and one child that resolved is now unresolved with that reason;
# - baseline_observations: that child's key loses its window occurrence (window_count 2 -> 1, last_ts follows);
# - baseline_window_counts: 1,119 -> 1,010 rows: tokens of the bl.ext_dest hours one cell covers whole are folded into
#   per-key counts (token ""); hours shared by cells keep one row per token;
# - audit: the material block's bytes follow (921,326 -> 842,654), and the exec-pair writer reason names the break.
# Candidates, links, tasks, events and every non-baseline cell are unchanged.
# A break now blocks only the parent-to-child intervals it can fall inside: each record not carried breaks at its own
# instant (its whole hour only when its instant is untrusted), and coverage reasons fold into classes with counts:
# - rule_cells: 4 bl.exec_pair window cells (14:10-14:15, 14:30-14:35, 14:36:15-14:36:33.75, 14:38:26.25-14:38:45)
#   become evaluated_complete with no reasons: each held one web1 child whose parent exec 41 s earlier was carried
#   and whose interval holds none of web1's unknown-boot exec instants (they fall before the parent or after the
#   child), so the hour-wide break no longer blocks it. Children whose break instants all follow them read "parent
#   exec in an unobserved hour" instead of "an exec of the host between parent and child was not carried". Every
#   other exec-pair cell's reasons are the same reasons stated as classes with counts and example ids;
# - baseline_window_counts (+43 rows), baseline_window_scope_hours (+9 rows), baseline_hunt_exclusions (+7 rows):
#   the four complete cells' exec-pair keys are now counted; two keys are new and five gain one occurrence, so
#   baseline_observations has 349 rows (exec_pair unresolved 203 -> 205, all "no pre-window history");
# - baseline_observations, tasks, audit, manifest: the history failure states the hours its class covers ("history
#   gap: fixture has no pre-window history (504 hour(s))"); exec-pair window_failure reads 22 partial cells (was
#   26); the manifest rule coverage follows (exec_pair evaluated_complete 10 -> 14, evaluated_partial 27 -> 23) and
#   its coverage gaps state 205 unresolved keys; the audit's material bytes follow (842,654 -> 876,222) and the
#   exec-pair writer reason cites the first still-unresolved record.
# Candidates, links, events and every non-baseline cell are unchanged.
# Where the kept execs cannot name a child's parent, a process observation of it may, when it follows the latest
# kept exec of that process and nothing between it and the child (a break, an unobserved hour, an evicted exec)
# could have replaced its image; before, a gap in observation anywhere earlier (13:50-13:55 here) kept it unused:
# - rule_cells: 6 bl.exec_pair children now resolve, each the child of a /usr/bin/vi process seen only in its own
#   audit records about 39 s before the child, with observation unbroken from then on (5 read "parent exec in an
#   unobserved hour", 1 on web1 "an exec of the host between parent and child was not carried"; that one's
#   observation follows web1's break by 2 s). Window cells 4 more evaluated_complete (14 -> 18), two cells lose one
#   reason, and the exec-pair summary cell states 18 partial cells and 211 unresolved keys;
# - baseline_window_counts (+79 rows), baseline_window_scope_hours (+12 rows), baseline_observations (+6 rows, all
#   unresolved for the fixture's absent history): the newly complete cells' keys are counted;
# - audit, tasks, manifest: exec_pair observations and unresolved 205 -> 211, window_failure 22 -> 18 cells, rule
#   coverage evaluated_complete 14 -> 18 and evaluated_partial 23 -> 19; material bytes 876,222 -> 936,342.
# Every other digest and the non-baseline semantic projection are unchanged.
# The first Windows process-centric rules join the pack. They are scoped to Windows telemetry and read no Linux
# family, so on this Linux-only fixture they produce no finding: every candidate, lane, claim, citation, link,
# anchor, expansion row and the candidates semantic projection are byte-identical. They do add their own coverage
# cells (every rule gets a cell per target and partition): the rule_cells table gains the 25 rules' per-partition
# not_applicable_no_events and split cells and their positive-only window cells (3,759 -> 5,534 non-baseline cells),
# and the report manifest's coverage block lists them. rule_cells and manifest change by those cells only; events,
# raw, entities, tasks, baseline rows, anchors, links and expansion are unchanged.
# The W1a fix round makes every Windows process rule positive-only (ROMULUS never asserts absence) and bumps the
# versions of the rules that changed (lineage, remote, dcom, service, inhibit-recovery, defender, firewall,
# security-service, log-clearing, rundll32, curl). On this Linux-only fixture those rules still produce no finding,
# so the candidates semantic projection stays byte-identical; their window cells move from not_applicable/complete
# to positive_only and carry the new versions, changing rule_cells and the manifest coverage block only.
# The reviewer's second fix round (shared interval-history lineage, exact native-messaging recognition, Defender
# key path-components) bumps the versions of the parent-resolving and Defender rules again; on this Linux-only
# fixture only those rules' rule_version in rule_cells changes (candidates still byte-identical, manifest stable).
# The third round (immediate publication of parent-resolved findings, finalize corrections, staged citations) bumps
# the parent-resolving rules once more: again only their rule_version in rule_cells changes on this fixture.
# In-place revision of published findings (a late record's correction, a merged finding's final tally) changes the
# wording of every Windows process rule's revised claims, so all of them carry new versions; on this Linux-only
# fixture only their rule_version in rule_cells changes.
# A merged finding now takes out records whose parent a later record withdrew (and the admin-share rule cites the
# parent it resolves), so the four parent-resolving rules carry new versions: again only their rule_version in
# rule_cells changes on this fixture, and the candidates stay byte-identical.
# The report's per-rule coverage field states what each rule searched instead of a negative claim (search_result:
# 'searched in full: N record(s) evaluated, none matched', 'searched in part: ...', 'no data in scope for this rule',
# and the positive-only texts no longer present absence as a later goal), so only the manifest digest changes; findings, cells and every other digest are unchanged.
# Fleet host paging changes Windows rule versions in the Linux coverage inventory.
# Candidate fields, citations, lanes, raw records, links and the manifest stay identical.
# Windows proxy, script, citation and bounded-revision semantics increment Windows rule versions.
# Only rule_version changes in 6,887 coverage cells across 97 Windows rules in this Linux fixture.
# Restoring those versions reproduces every table and semantic-field digest; all findings remain identical.
# Reading Zeek's alerts bumps net.suricata_alert_stack 3->4, corr.process_network_link 9->10,
# net.dns_zone_transfer_or_any_request 5->6 and ioc.indicator_match 5->6, adds net.zeek_alert (pack@43; its cells are
# new rule_cells rows) and changes nothing else: with those versions restored the candidates digest is the earlier
# 3b23f98d..., and rule_cells and manifest differ only by the new rule's cells and the pack version.
# Zeek conn reading increments net.protocol_port_mismatch 7->8, net.long_unidentified_session 6->7,
# net.outbound_volume_asymmetry 5->6 and net.port_scan 10->11; only their rule_version changes (in candidates,
# cells and the manifest). With all eight versions set back and net.zeek_alert left out of the pack (pack@42),
# every digest of GOLDEN_STACK is the earlier one: candidates 3b23f98d..., rule_cells 0ede3bea..., manifest
# 35b8a013..., and every other table as it was. The sweep's Zeek plumbing (per-family coverage of records no
# normalizer read, Zeek deduplication, the rule guard) changes nothing in this fixture.
# Additional Windows readers contribute zero-evaluated coverage cells on this Linux fixture.
# Seven changed Windows rule versions also affect coverage only; every prior cell field is
# identical after restoring those versions. Findings, citations and other stored tables are unchanged.
# Nine Windows rule decisions changed their versions. In this Linux fixture they evaluate no records;
# restoring those versions reproduces every coverage-cell field and all other table digests.
# Only the rule_cells fingerprints change; the manifest, findings and citations are identical.
# The server/startup child rule's later version bump likewise moves only rule_cells.
# Three Windows RPC rules add only their zero-evaluation coverage cells and manifest rows here.
# Removing those rules and incidental coverage row ids reproduces the complete prior snapshot;
# every finding, citation, raw record, event, link and other table digest is unchanged.
# Coverage includes 36 additional Windows/Zeek rules with zero evaluated/matched records here.
# Removing their 2,556 cells and 36 manifest coverage rows, restoring seven registered rule versions,
# and restoring incidental coverage row IDs reconstructs the complete prior snapshot exactly.
# Findings, evidence, links, requests and all 21 non-coverage section digests remain unchanged.
# Rate coalescing and early-hit semantics, plus canonical preview/MSIX PowerShell,
# bump five network rate contracts and the PowerShell server contract from 3 to 4.
# This fixture has no qualifying rate/PowerShell/analyst-indicator/Sigma matches:
# its only changes are 426 rule-cell versions (71 cells per changed rule).
# Restoring those six named versions reproduces every field in all 23 sections;
# all 35 candidates, citations, lanes, the manifest and normalization stay exact.
# Rate replay checkpoints, ASCII PowerShell parents and typed HTTP/body indicators change only 497 coverage
# versions here: 71 cells each for the five rate rules, win.unexpected_ps_remote_server and ioc.indicator_match.
# Restoring those seven named versions reproduces all 23 complete sections; the 35 candidates, claims, lanes,
# citations, requests, evidence, manifest and every other field remain identical.
# Port-aware HTTP indicator matching and kind-scoped coverage change only the IOC contract version in its
# 71 cells here. Restoring that one version reproduces all 23 sections, including every candidate and manifest.
# Shared flow inputs retain the same 35 finding identities, lanes and severities. Three beacon findings cite
# Arkime first and retain Suricata witnesses, with unchanged connection counts and interval statistics;
# the other 32 findings are exact. Added witness rows, entity links and exclusion targets follow those citations.
# All 639 changed coverage cells differ only by the nine changed rule versions.
# Folded alert findings cite follow-on executions, so their discovery and staging are not repeated as context.
# The 42 candidates preserve those observations and lanes; credential readers fold by executable and path.
# Changed anchor groups, coverage versions and expansion selections account for the related fingerprints.
GOLDEN_STACK = {'anchors': '41228c5a5ac779a4178656ed1292cea125732d2991b15312e6a2286e6beb1303',
 'audit': '17723a028519c6af79535fda9f3166cb3bd6900027465e394a84cb31f2dfcf6d',
 'baseline_counts': 'be05fabb25336f21341b46eae7d8c2627828f7a7a7e8fdb24f4eb58576099354',
 'baseline_hunt_exclusions': 'c91eefda01c512d6d63e892dc9696016b01a71d44e4abcc429d954bd51864852',
 'baseline_observations': '2cac5f0f0a1107fa58648643db52a5fe64ff346e0d521e28aef302aca10fd2c3',
 'baseline_scope_hours': '0a1ce00b7f354753a35786774c98b43f73c6eecd0ac53c5283b89702968894fb',
 'baseline_segments': 'a3e22e8301643a23a9a9fd591a56a8b6baa65f55c31f3cfb9f910a6a639694fa',
 'baseline_snapshot': '63b4c8094cb5450b1e707fd7be786e90324528e738b882358cae15cb8d53f776',
 'baseline_window_counts': '7cc0f5555260b0533927f47cfe29e6a543e2d921b0cc79e4b6b89f418d6052f8',
 'baseline_window_event_hours': 'bb58c65144b135443e75a690b7b2f8137ebac6b827f8e8bd8cc7606a01c53e52',
 'baseline_window_scope_hours': '9e290626d76b423e9aed82a63d54fc6c2d6a2feeea3b55297ed76696c9279c80',
 'candidates': '9f84a6717d0a98d5ed6010fd7834202ef871de9db22e9af8089ae802c2a0c081',
 'entities': 'f26a3ccda6f16d94a0b0822914a0827ecd57ab81791dec1e39227f76a3529f17',
 'event_citations': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'event_entities': '73eb1a7cb37581de8b25ae6079e62e8f2a58b4e75697820e4ae41ac414064773',
 'events': '731e19f952d06603a6e19d7204fb7c1d53de79ad4207d21c3dc3bfda20787e9d',
 'expansion': 'a9cee30177095cf3d5186cb43f16a09b1811cba4f286ffc9bc8ddc32c76e1f10',
 'links': '8fb8da9a2bfc8fca7eac6f0361659105d14345cf6d683d63817ce0829eabe673',
 'manifest': '17e916afc9a75a11f375b4116fbc65d906e49ea9c812d43aaa5bd7eec99c2789',
 'raw': 'b85b03c11c502b9e1e1f05702cd348b5ec1e79fb661a787fa6bf4c39dc31d871',
 'rule_cells': '14f4a1d4f979712ba6a3d88f7fb973a98a968aff80d95d79fc4ff343defb9915',
 'stats': '18fcb2f6b78a17228b3a60b50bd103d66b5a07884252c753349b21b12889ced5',
 'tasks': 'aff8bcff2641089d919982d0ec3b13034f2dd1ab2ffa4e4416db6cbfe3220cfa'}
# Captured directly from the S7 fixture through _non_baseline_semantic_digests. Typed-event-derived hashes and
# interchangeable predicate origins are normalized, while every decision, claim, lane, raw citation and gate is
# checked field by field.
GOLDEN_NON_BASELINE_SEMANTICS = {'candidates': {'all_fields': 'f9197e6dcf1847905144bc5eeb228e84a2d4fc96e2aade996d544a0c63101e62',
                'benign_alternatives': 'f90394be6d9c964191389d2c2108d76de9a2e583feb94a1b9c5a2b95ee5ac78d',
                'claim': 'f66a07a1a0005ba2a13c3383df0215e8974cda67d8039551bdeab947360faaa6',
                'claim_type': '3cd6011d54362d285031a4c88ef2c9ebbb55804fa39da53138105d0a18448a64',
                'confidence': '3c288652612672958bde6e2008a312116ea5538b857c0701b6788243653d015e',
                'context_event_records': 'ff75b8fc0962906fa032df9a3c29bc61ada420d3a548d515c3328d45760ece22',
                'count': 42,
                'entities': 'ec4dd90655858d6f87c9b86ccdec64b906a157d7e222e6e234bc40b5377e49ba',
                'event_records': '14f3a8da641d919c21f52cfef3c9b4114a8f75e6baf4abcce95f5ab0099827ae',
                'gate_results': 'db7111bb9a970c32cd0ae4af06ae2821ec9e0c7377d8e9a4b9c823fe98a541bd',
                'group_key': 'b4200133e27a5c479df40753ef0f9d75d5dc1d1823fd6e6276166034a96bf7f9',
                'lane': '293874d2f54d67987e40f473eb4dd0a70c02323f69a9d309ba8e6dbd9fb11078',
                'next_checks': '876a439312382198f1f04293df5853fbac5dc05fa14fe9163365f981106614ff',
                'predicate_fields': '7ee4c5adb14d25919e21b172db01bcdbb01c11ee63eaccd37b5f6723e3af4f11',
                'priority': 'd519701a3e950f204b6136a2b02eec059796852a750318789e1f6dce7bc3ddf3',
                'priority_reasons': 'dd2f1e9f857f375c26ab7334e8cc1463c68c45d0316724a6c106c7365ead8f0e',
                'rule_id': '0572fb0dba8b16de3a1bbea7652dbbaf52718636a4080bd1fd03304b28b7e062',
                'rule_version': 'bf4e8a317fb82506c0153fa0e2bb4775711232064a5401d3d0dcb1e62e7c7d8e',
                'severity': 'fa0e16a58cb764a8ae958fbde474648dfe753ee8bd14593c9d56c74fb39a620b',
                'source_presence': '3770c51822192b772dfb9df91031b662cb6e5877a4cc5a569d3bb9ed831e649f',
                'ts': 'e60f4ddf845fc42727b5b4f6cf23a672b0fb2f2ec221ca3c6ba071a67bcc6b82'},
 'rule_cells': {'all_fields': 'c636e29653e376cb4ef294df517cd1f2b2c08747628b1521e8d017da98264650',
                'count': 17220,
                'detail': 'b2d0a2a7ba4b1a51412c1e923f58f47f630e981b843abbde1b84f8253a9440f2',
                'evaluated': 'ef1cccfa6ec23d7a5eb73d5f1c7786bb37860a8d48338291ad7d6007825953f9',
                'matched': '864628001c8b636cf52eb109dadba1cc1325af343b59359e67b3803ccff18936',
                'partition': '85fddca5c66ae8a33cfa2a65e93546cb013b4f4e5154b47c7827a402f317e8d8',
                'rule_id': '9260f06a98952a5a822d34f7c9a249ae41bd6bbc5946791b251736c9163b3bc4',
                'rule_version': '6a8cc559acfcd0ef8a6d38bdb260663c9968c50debc8d33688c906fa190623eb',
                'state': 'b7d0fe039645057d8785073e552869415d06897e4689393932de95b20d70d18f',
                'target': 'd07123225c1c59d2a50c738dfef667634c86add0db6fc35ac4c8c2ea03a00557'}}
GOLDEN_NORMALIZED = {'arkime_sessions3-x': '7407ea2345be798c29751a3c9470e3b6988dac5ce7d9f5d5c2ffe3b0bb3f7903',
 'arkime_sessions3-x+boots': '7407ea2345be798c29751a3c9470e3b6988dac5ce7d9f5d5c2ffe3b0bb3f7903',
 'romulus-host-x': '4e8ce0a9d2d59e3e151dfcbfca4b04554cb4f10a54b1b397a6ea58eec4f5eb07',
 'romulus-host-x+boots': '4ab87c943028621abc97523151d5ec6bef2ef830d4e2a7d92e7b47fe3f0ddd58',
 'romulus-network-x': 'edf93ea9388d54c1a11c9d70f00c9a4b3983db78c49b932ee329abdd284dd62c',
 'romulus-network-x+boots': 'edf93ea9388d54c1a11c9d70f00c9a4b3983db78c49b932ee329abdd284dd62c'}
GOLDEN_PIVOT = {'arkime_sessions3-x:-': '357d03e5670c22460621706ce9b6785674d8f6d309c2478804a51b1e0e6288db',
 'arkime_sessions3-x:process_exec': '357d03e5670c22460621706ce9b6785674d8f6d309c2478804a51b1e0e6288db',
 'arkime_sessions3-x:net_socket': '357d03e5670c22460621706ce9b6785674d8f6d309c2478804a51b1e0e6288db',
 'arkime_sessions3-x:auth,net_socket,process_exec': '357d03e5670c22460621706ce9b6785674d8f6d309c2478804a51b1e0e6288db',
 'arkime_sessions3-x:net_flow': '357d03e5670c22460621706ce9b6785674d8f6d309c2478804a51b1e0e6288db',
 'romulus-host-x:-': '663808ac8bf97c61934e034d7f8d6287d5d77c4e3cc017cc8eac661ed367769a',
 'romulus-host-x:process_exec': '4de5c5d736e871578fcabb841538920933b5bc6cee5bd3b2315723aa685da491',
 'romulus-host-x:net_socket': '60715318e2fff9d65306d497ff6e1144ea6047d57448ccef530912796a884b78',
 'romulus-host-x:auth,net_socket,process_exec': '663808ac8bf97c61934e034d7f8d6287d5d77c4e3cc017cc8eac661ed367769a',
 'romulus-host-x:net_flow': '663808ac8bf97c61934e034d7f8d6287d5d77c4e3cc017cc8eac661ed367769a',
 'romulus-network-x:-': '8b9780ca17a4157880f10de03ff0f9c06d22967ad5cf98f8525009dd31e1c8ab',
 'romulus-network-x:process_exec': '9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6',
 'romulus-network-x:net_socket': '9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6',
 'romulus-network-x:auth,net_socket,process_exec': '9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6',
 'romulus-network-x:net_flow': 'c534a2f3f53bd027e7f90efe3e1e05342719bb957407b67cf8a708afb185ca96'}
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
