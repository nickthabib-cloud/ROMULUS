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
# New host rules add four direct findings and five context findings; all prior findings and their
# native citations remain. Two additional anchors share the fixed expansion budget, making eight
# previously complete links explicitly partial. Producer IDs, native host.ip fields, coverage versions,
# new-rule cells and derived baseline exclusions account for the remaining pin changes.
GOLDEN_STACK = {'anchors': '61171ea12839cbb8f691f31c6556ce62cc1d2aa072d0e3c41eb1fa1179e77084',
 'audit': 'd82d7d7947533831e26fad537080b915528ba20a1b0950ae3def735aa13652be',
 'baseline_counts': 'be05fabb25336f21341b46eae7d8c2627828f7a7a7e8fdb24f4eb58576099354',
 'baseline_hunt_exclusions': 'c91eefda01c512d6d63e892dc9696016b01a71d44e4abcc429d954bd51864852',
 'baseline_observations': '2cac5f0f0a1107fa58648643db52a5fe64ff346e0d521e28aef302aca10fd2c3',
 'baseline_scope_hours': '0a1ce00b7f354753a35786774c98b43f73c6eecd0ac53c5283b89702968894fb',
 'baseline_segments': 'a3e22e8301643a23a9a9fd591a56a8b6baa65f55c31f3cfb9f910a6a639694fa',
 'baseline_snapshot': '63b4c8094cb5450b1e707fd7be786e90324528e738b882358cae15cb8d53f776',
 'baseline_window_counts': '7cc0f5555260b0533927f47cfe29e6a543e2d921b0cc79e4b6b89f418d6052f8',
 'baseline_window_event_hours': 'bb58c65144b135443e75a690b7b2f8137ebac6b827f8e8bd8cc7606a01c53e52',
 'baseline_window_scope_hours': '9e290626d76b423e9aed82a63d54fc6c2d6a2feeea3b55297ed76696c9279c80',
 'candidates': '7feeec34152612d99f26f626457058d6b4dc627289c56914d4985e6863675d37',
 'entities': 'e9ff16ac60f541b0049687f4f2bc7f99227ee4c313c2b8fa6c07d8a9c05cc600',
 'event_citations': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'event_entities': 'c7dfa9aff120bcb6cfc45f3e0031432c1ce92ed217bb85f1389ef08d4bfa23ab',
 'events': '96d4ef738b9a00830c0536b40b3692647b55dac8ba8ecf9d5b384ab1e1fef481',
 'expansion': 'f8234ee143ca1765bc4f3d8043359e452bb4efb42761f11024e84f957255ed7c',
 'links': 'f8b551e237f625c725757063d1871afcc9e91614bb852e66ecc508fc94a8dfa1',
 'manifest': '697ed457779a48d680750c05d0973234cb1aa9bdb12303d14a80b639ea74e790',
 'raw': 'de4835b8249e2f3a3229432287abfb721610df89d428b1b7fdc58f2955fc8d60',
 'rule_cells': '4bc761d32754f1daa7b6243d949c68c9b18692971c573e397c398c857d897bc5',
 'stats': '18fcb2f6b78a17228b3a60b50bd103d66b5a07884252c753349b21b12889ced5',
 'tasks': 'f99dea5bd1fdd4c2169e2db44d356a7513eddd37f267716e42a47350533a1e21'}
# Captured directly from the S7 fixture through _non_baseline_semantic_digests. Typed-event-derived hashes and
# interchangeable predicate origins are normalized, while every decision, claim, lane, raw citation and gate is
# checked field by field.
GOLDEN_NON_BASELINE_SEMANTICS = {'candidates': {'all_fields': '4ee8774dd5308542f7eff4fec3ddbd6b39efa63faf3c48672b932725bf43dbd6',
                'benign_alternatives': '4733fa88bf9317661ca2652c8459fc7282eadbab4362473f72c703a180be1b36',
                'claim': '6a18d094fb915696125686b838065e73f3f621a556ebdbc67371e609b7737da8',
                'claim_type': '96a74f6a83bd86fbe5a7673eb4c4745af0e8bc106b13b138448bfdea9f030a5f',
                'confidence': 'aefa257654a688b725b94a72136dd14cadfd3e19fc49d81e27cce1119f9e019a',
                'context_event_records': '6a0063aca0345533340995243cdf96321e174ebccc23544229c63c2de19618a6',
                'count': 44,
                'entities': 'e9240ac5308fb6d3e91741ccbf0117eee4a74a2a2aaf5e08068227da46a8929a',
                'event_records': '6031b9cd15a4ebd9699868acfc2afc859a7ae493e204f1588119b828e42039ba',
                'gate_results': 'f1df78bbdbeebfea07ecdef5be4a007dc98e11126ebd069e1b7a5e4dba5277af',
                'group_key': 'a1608735407fd727b9dacfecdf16bac870e132a2475166556445d0aff5c1eb9a',
                'lane': '52fb123d2c5c15000167213caa79802fc0398d44e528bcbca7bd57e5042cabb3',
                'next_checks': '2b474d2db3f68f684eebe27c2bcf34138ebc495ab5c44ffd4934f7c9991d213f',
                'predicate_fields': '6603c8de2982d05a78618cebd07a85722a663640393b9505898965cec3fbba41',
                'priority': '0ffcb1addeaf98c5fe0641e899da4b34e7abe8100cc12a85df5558a7c34f31e5',
                'priority_reasons': '46c0090742799c5a633401ad24e71bfc09e6100169c5b5c041635b34797a456b',
                'rule_id': '82ea74649fdf4b16f172c96942b6595ecf827e0d206724501b3535f0576442bd',
                'rule_version': 'a599484818450cc09740418f22b42b2e321d3045e3468a21bd99823d7a0cc423',
                'severity': '4e334523ee8c15fb2fd2a1595e22ff3f76ac2297fb0b7e79097e3ee3bf6657a6',
                'source_presence': 'e24a039246b9e2de02b32d6cab108f267eab8df71909302dca192af029b0fede',
                'ts': '3b9ed73b3d87d747c7736b5b1dbceb1f0209cab02b4e513f1b35a08584bfc9e1'},
 'rule_cells': {'all_fields': '119b594d5fa1c5562c36deef6f013923c786cbb6e4b380917a5cb22bffc7af4a',
                'count': 17118,
                'detail': '0835ac4c6208e513adedd7046ed3d4768b714bf91c6d5118f823081690165b36',
                'evaluated': 'ca78a0f36038ed91bc8ec07eb103bf6b911909077e5f496e0ef59667f69f52d7',
                'matched': '6f779e6a0fff4134aa44cfa9ba0e37f147442ae8a3f937d02056d4462fd04b85',
                'partition': 'a8d806a553b316d9f8996a2dce82b3ba6ad96118198817a467cb8eee272ec224',
                'rule_id': '647162080e42dfb91b7a444160dfdd04e641059f7f28fa043cf99dad33815575',
                'rule_version': '2c48b1bb206860c88cb74ec7d9da9ab7558a7879769893923e349a853832e751',
                'state': '4c575c56c49ecaa2c0be0d1c2b80fb396817e9c0a6353ee782164c9355d07369',
                'target': 'fae14e9211bd18d4c50cd72e560e38da9b318818b85110583ffda01143654f00'}}
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
