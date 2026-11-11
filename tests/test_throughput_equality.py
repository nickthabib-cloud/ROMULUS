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
# Root commands descending from the web account's reverse shell join the folded alert, so two more duplicate
# context links from that anchor are cited there instead (40 candidates); the direct shadow read and the
# labelled lateral SSH and staging context items remain.
# Changed anchor groups, coverage versions and expansion selections account for the related fingerprints.
# The evidence epoch moved (Linux shipper shapes, lab-ecs@16): every typed event id is rehashed, which moves
# every digest over event ids (events, candidates, citations' event lists, links, raw first-task ids through
# the query plan, and the normalization and pivot goldens). The sweep's Linux query names each logical dataset
# (the new linux.syslog among them) and the compiler expands it to its shipper names, so task fingerprints and
# intents, the dataset_filter in stats, audit and manifest, and the new linux_shapes / linux_shipper_inventory /
# linux_shapes_not_assessed stats change. With the evidence version set back to 15 every other digest is the
# earlier one, and the non-baseline semantic projection (every decision, claim, lane, gate) is unchanged.
# Auditbeat documents without a dataset are a shape of their own: this target cannot select them (no
# event.module), so linux_shapes_not_assessed names it too, moving only stats and the sweep summary audit row.
# The evidence epoch moved again (lab-ecs@17: Elastic-shipped Suricata and NXLog flat Windows records are read):
# every typed event id is rehashed, which moves the digests over event ids (events, candidates, event entities,
# links, audit, manifest, rule cells, the baseline observations and scope hours, and the normalization and pivot
# goldens). With the evidence version set back to 16 every digest here is the earlier one, and the non-baseline
# semantic projection is unchanged.
# Evidence ranking runs before and after expansion. Expansion seeds what the rule estimate seeds (urgent and high)
# with the budget share and order it always had, then the ranking's Reported findings on entities that carry a
# confirmed finding, with the budget left. This fixture has no confirmed finding, so its 23 Reported leads sit on
# entities reported for breadth alone and give no extra seed: the ranked stack anchors exactly the rule estimate's
# seeds, and differs from it only in the audit (the two ranking pass summaries) and the manifest (each finding's
# rank fields, the ranking summary and the ranked entities).
# Rule tactics are now resolved through the vendored ATT&CK release (the old technique table is only a fallback), which
# moves the attack_tactics (and the narrative's mapping sentence) of 10 of the 24 incidents: the release's tactics
# replace the table's defense-evasion with stealth or defense-impairment (Valid Accounts, Impair Defenses), and add
# exfiltration, collection, impact, privilege-escalation and command-and-control where the table had fewer or none
# (I-1e61a68c9c35, I-bda21460664c, I-dbb6b7f023dd, I-2d9388d67b6f, I-35a2807ebb9c, I-64996482cb56, I-5c6b5f2d653a,
# I-9bf75eb45f37, I-b7971accd14a, I-fb7b4afcec47). Incident membership, techniques and everything else are unchanged.
# Bare local accounts are qualified by their host, so the manifest's entities name web1\www-data and db1\alice
# instead of www-data and alice.
# Run with expansion seeded by the rule estimate (`run_stack(rank=False)`), every digest is the earlier one except the
# manifest's (those incident tactics alone), and the non-baseline semantic projection is the earlier one.
# Re-pinned 2026-11-10 for Linux text support, with each movement compared against the prior snapshot:
# - events, event entities, entity rows, citation rows, anchors and expansion are byte-identical. All 40
#   candidates retain their ids, decisions, claims and evidence; one persistence candidate changes only its
#   rule_version from 8 to 9, identifying its expanded cron contract. No candidate is added or removed.
# - rule_cells: seven rules add 499 cells; later numeric row ids shift. Twenty-seven existing journal-error
#   cells narrow to partial because malformed journal records can hide DNS, firewall or proxy events. The
#   persistence rule's 71 cells change version only: all evaluated/matched/state/detail values equal the prior
#   snapshot, so unrelated service starts no longer inflate the 22 affected evaluation cells. Existing baseline
#   cells also reference the new snapshot digest; bl.ext_dest records its journal-error window partial.
# - baseline_snapshot: adds the VPN source-history specification and its three unresolved target coverages.
#   baseline_segments adds three empty complete segments, while baseline_window_event_hours adds one VPN
#   specification row (four auth-family input events, zero VPN observations). Other baseline tables are unchanged.
# - tasks: Linux raw-selection intents include linux.text and the baseline plan includes the VPN spec, changing
#   fingerprints/ids and the baseline outcome. The same 175 tasks and 135 queries return the same selected data.
# - raw and links: only first_task_id / task_ids references change; all 436 raw payloads and 156 link results match.
# - stats: adds the explicit linux.text-not-searchable note for this fixture's unmapped text payload fields.
# - audit: mirrors that note, baseline snapshot/spec/partial changes, three added segments and material bytes.
# - manifest: mirrors new rule/baseline coverage, honest partials, the persistence version and its expanded title
#   in one incident narrative. Findings otherwise match; attachment coverage explicitly states no MTA producer.
# The separate text-stack fixture pins actual content retrieval, auth/mail/VPN findings and unknown-line coverage.
# The ranked stack: its expansion anchors are the rule estimate's own (this scenario's Reported leads sit on
# entities reported for their breadth alone, which give no extra seed), so it holds the rule-estimate stack's 40
# candidates and baseline; it differs from that stack only in the ranking passes, their audit and the manifest.
# Evidence epoch 18 rehashes every event id, and Suricata and Arkime records carry their own producer identities:
# with the evidence version, the Windows producer and the network producers set back, the two new network rules left out of the pack and the network rule versions restored, every table is the earlier one except the manifest's reworded network positive-only reasons and its pack digest.
GOLDEN_STACK = {'anchors': '3214bd0b324534f0828d1ed45fd25dc113e8da587e5690e1fe554935eb6f87cf',
 'audit': '873f48a03d7f75bd788f145df400fdf6a99922ee26c5b84980e2b11bf49940fa',
 'baseline_counts': 'be05fabb25336f21341b46eae7d8c2627828f7a7a7e8fdb24f4eb58576099354',
 'baseline_hunt_exclusions': 'c91eefda01c512d6d63e892dc9696016b01a71d44e4abcc429d954bd51864852',
 'baseline_observations': 'e29a1a399ddbcef146c74d1abd68ff6d89e0b2ffbc0f0779164bb6d83f6e999b',
 'baseline_scope_hours': '0a1ce00b7f354753a35786774c98b43f73c6eecd0ac53c5283b89702968894fb',
 'baseline_segments': '48b1a281c368bcd572e5e8d624d40030a9f4bec575ab0195fc6659b4410feafe',
 'baseline_snapshot': 'c4d83cc473697b70a3d6d02e3b4fd86ff6f624e0c80a41e4ddacbc54fb663353',
 'baseline_window_counts': '7cc0f5555260b0533927f47cfe29e6a543e2d921b0cc79e4b6b89f418d6052f8',
 'baseline_window_event_hours': '073d2b603455282038d461b6a111095c59b3a3116f5e0d7e95c78f2e5cec4122',
 'baseline_window_scope_hours': '56d34f2dc6bff9a81d819e7e0e3be52768e0985ed663c4090170acb1fc9135bf',
 'candidates': 'b3634f743e803960bf2a332474fe4048e5b3fa9ef36c1b2b936c5e3d7c62b9d8',
 'entities': 'f26a3ccda6f16d94a0b0822914a0827ecd57ab81791dec1e39227f76a3529f17',
 'event_citations': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'event_entities': 'c4247d1675ef28e74c419b8652c03bf96699cea97e5fcca8699d8a42dea2f4e0',
 'events': '7f910bb15263f11b185598481b817c2693fdbb68516dbdd67b402154f55f37d8',
 'expansion': 'e7a94c167f9a42d9adb20a9ee7660abd45c407ecf30baf023f31b465f0b845fa',
 'links': 'd5698df5cfe56135a39bffc6ecc055d4b896a46799f5b9087af27fc16e60cabc',
 'manifest': '300c161f3ccd6972020386a79853df20da2e9eb2230db591b2469bd4dd799f2e',
 'raw': 'd924f62eebd5ee88c8142c690333924450c3344b18210ddfe87b8e486127dd35',
 'rule_cells': '81d5f330e18075bf83eed66db3d4926b60b7310a71027798e6da013b4ef0e871',
 'stats': 'be588e34e14e570c11a47fc9b3953e564d8f6026d909d9ae7f9c7ef561c99c5a',
 'tasks': 'bafebe65e787ccfaf77d643cc10a1aa59b0f8ec5faa84078d23656eeafb6e0b6'}
# The rule-estimate stack's digests (expansion seeded by the urgent and high lanes, as before evidence ranking;
# the manifest's moved only with the incident tactics above).
GOLDEN_STACK_BY_RULE_ESTIMATE = {'anchors': '3214bd0b324534f0828d1ed45fd25dc113e8da587e5690e1fe554935eb6f87cf',
 'audit': '1d459a42cf823b8c23e426cb552081fcd521d6dcaa78198641d6731810de5c88',
 'baseline_counts': 'be05fabb25336f21341b46eae7d8c2627828f7a7a7e8fdb24f4eb58576099354',
 'baseline_hunt_exclusions': 'c91eefda01c512d6d63e892dc9696016b01a71d44e4abcc429d954bd51864852',
 'baseline_observations': 'e29a1a399ddbcef146c74d1abd68ff6d89e0b2ffbc0f0779164bb6d83f6e999b',
 'baseline_scope_hours': '0a1ce00b7f354753a35786774c98b43f73c6eecd0ac53c5283b89702968894fb',
 'baseline_segments': '48b1a281c368bcd572e5e8d624d40030a9f4bec575ab0195fc6659b4410feafe',
 'baseline_snapshot': 'c4d83cc473697b70a3d6d02e3b4fd86ff6f624e0c80a41e4ddacbc54fb663353',
 'baseline_window_counts': '7cc0f5555260b0533927f47cfe29e6a543e2d921b0cc79e4b6b89f418d6052f8',
 'baseline_window_event_hours': '073d2b603455282038d461b6a111095c59b3a3116f5e0d7e95c78f2e5cec4122',
 'baseline_window_scope_hours': '56d34f2dc6bff9a81d819e7e0e3be52768e0985ed663c4090170acb1fc9135bf',
 'candidates': 'b3634f743e803960bf2a332474fe4048e5b3fa9ef36c1b2b936c5e3d7c62b9d8',
 'entities': 'f26a3ccda6f16d94a0b0822914a0827ecd57ab81791dec1e39227f76a3529f17',
 'event_citations': '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
 'event_entities': 'c4247d1675ef28e74c419b8652c03bf96699cea97e5fcca8699d8a42dea2f4e0',
 'events': '7f910bb15263f11b185598481b817c2693fdbb68516dbdd67b402154f55f37d8',
 'expansion': 'e7a94c167f9a42d9adb20a9ee7660abd45c407ecf30baf023f31b465f0b845fa',
 'links': 'd5698df5cfe56135a39bffc6ecc055d4b896a46799f5b9087af27fc16e60cabc',
 'manifest': '64d2c833531d859c94952b6fc7ae79973dcb271a97ed00278e0625c15d608f05',
 'raw': 'd924f62eebd5ee88c8142c690333924450c3344b18210ddfe87b8e486127dd35',
 'rule_cells': '81d5f330e18075bf83eed66db3d4926b60b7310a71027798e6da013b4ef0e871',
 'stats': 'be588e34e14e570c11a47fc9b3953e564d8f6026d909d9ae7f9c7ef561c99c5a',
 'tasks': 'bafebe65e787ccfaf77d643cc10a1aa59b0f8ec5faa84078d23656eeafb6e0b6'}
GOLDEN_CANDIDATES_BY_RULE_ESTIMATE = GOLDEN_STACK_BY_RULE_ESTIMATE['candidates']
GOLDEN_NON_BASELINE_SEMANTICS_BY_RULE_ESTIMATE = {'candidates': {'all_fields': 'ce9f007dd782b98a0c29edb6d69ef7c49368283f86861274e96381b704c23de8',
                'benign_alternatives': 'b6a6498000e772cfa17ad8ec0de6611835534dbd7262543e97e6e413b75304aa',
                'claim': 'b9376dc415ee7a3f7cd11e025171c6aa7bcb0eb58af69169ddf7c8f0fa84653d',
                'claim_type': '62ee830737cd920223bd88ccd391e5074f2e72242803701f1f849e25d1fdf7c2',
                'confidence': 'fbdbcc65a374c9bad760df608732609bf67565a3af9922898c67e31f78636a01',
                'context_event_records': '812b2ee0a914612b78ec64e62317ee31cc172d0fe445880a23a7139bb9a8e1f4',
                'count': 40,
                'entities': 'a46018da750e2c05f29c1f50286e55174d6565c69b30892ce66b33b53c41de23',
                'event_records': '30bdb797329163379f3be620d3fc42e392e45fc65f4f91bfc66d1516a011b6ae',
                'gate_results': 'f8c8a0c7bf839e46be7d1bc87ccd9afc6602270f5fe27e4f9de166f10bf59d29',
                'group_key': 'f188f4672391c7c67237a2e55de7b94c8ae3aaddd5335ce0e82fe9a9b6df2b74',
                'lane': 'a523c12959469de5628f7ca065677e0e9d7f4c492857dc2d4942b625f3f125ca',
                'next_checks': '1af15e5ad4e85fe763b5475d34aff89c61ecdf6730648475909fcbcb64ff2e4b',
                'predicate_fields': '68b721cd4b7184f6191b023ca1889a7815d71a7f35d470a882a31cf230a034e6',
                'priority': '81a856684110a1b2b59396843facb23007b68eaf8c3c031222a8e9c1d5db1e06',
                'priority_reasons': 'd38e0586d04b87d7f11769084f0368af795f59c692d2debbb4dad2eaaca05150',
                'rule_id': '50045a80bc2eb3e1c66c58f0a55acfc5e8db0f87e8b18bd8772a1361b20c1313',
                'rule_version': 'f5b8180b2b81602eaabd25d2e8ac3e8609321f3f5318d81d2d80c36fe4d8be93',
                'severity': 'd8fb260b8a62f9175181cdba1356bfbd3dab9167f0965c5e7586e2202c62bcc3',
                'source_presence': '31f6a55e225e04f5da96ef7f565969408d500a329be1bf37e463188763a5af16',
                'ts': 'bfc0e0328d7a2b9fb224bc2791da7a13f533d4b8f03819ad9f65e7609fac08e0'},
 'rule_cells': {'all_fields': '20a1f915ccb294a04c1d67b497c0b31d8bf186067fab3d1cd3ca7a2a232158da',
                'count': 18252,
                'detail': 'bbae80694d9fc180c7836342da979ab0d91f37ee5143312ceb103abb905d8d7f',
                'evaluated': '0d54ccc8c705e92e49ba35fa799cddbabda8acc1df656c1fb2a43e3e9761416a',
                'matched': 'c8b1f90b1c4007b2fc6288d2be106dc78ec44426696421cc3a25525e4168f7d2',
                'partition': '6fed6d30078fb22922b265544eb4155d422474b17f432f1a08ef411ddacdefb7',
                'rule_id': '10c0cc056dbbc99dc8c6a5a790c54e5242b1236cb63fd919eb8fde0090aa19b3',
                'rule_version': '079694f2aec852eb4133858c98d13051fb9b01574da64a91c702325b8d94f953',
                'state': '4572ef37f568d25fe187a0b2b922337be74f55f9406b0f01970ac23048754f78',
                'target': 'b28323b5b8624bb63846a455929f49c23bff677df713eb2991f93ecaf29e2756'}}
# Captured directly from the S7 fixture through _non_baseline_semantic_digests. Typed-event-derived hashes and
# interchangeable predicate origins are normalized, while every decision, claim, lane, raw citation and gate is
# checked field by field.
GOLDEN_NON_BASELINE_SEMANTICS = {'candidates': {'all_fields': 'ce9f007dd782b98a0c29edb6d69ef7c49368283f86861274e96381b704c23de8',
                'benign_alternatives': 'b6a6498000e772cfa17ad8ec0de6611835534dbd7262543e97e6e413b75304aa',
                'claim': 'b9376dc415ee7a3f7cd11e025171c6aa7bcb0eb58af69169ddf7c8f0fa84653d',
                'claim_type': '62ee830737cd920223bd88ccd391e5074f2e72242803701f1f849e25d1fdf7c2',
                'confidence': 'fbdbcc65a374c9bad760df608732609bf67565a3af9922898c67e31f78636a01',
                'context_event_records': '812b2ee0a914612b78ec64e62317ee31cc172d0fe445880a23a7139bb9a8e1f4',
                'count': 40,
                'entities': 'a46018da750e2c05f29c1f50286e55174d6565c69b30892ce66b33b53c41de23',
                'event_records': '30bdb797329163379f3be620d3fc42e392e45fc65f4f91bfc66d1516a011b6ae',
                'gate_results': 'f8c8a0c7bf839e46be7d1bc87ccd9afc6602270f5fe27e4f9de166f10bf59d29',
                'group_key': 'f188f4672391c7c67237a2e55de7b94c8ae3aaddd5335ce0e82fe9a9b6df2b74',
                'lane': 'a523c12959469de5628f7ca065677e0e9d7f4c492857dc2d4942b625f3f125ca',
                'next_checks': '1af15e5ad4e85fe763b5475d34aff89c61ecdf6730648475909fcbcb64ff2e4b',
                'predicate_fields': '68b721cd4b7184f6191b023ca1889a7815d71a7f35d470a882a31cf230a034e6',
                'priority': '81a856684110a1b2b59396843facb23007b68eaf8c3c031222a8e9c1d5db1e06',
                'priority_reasons': 'd38e0586d04b87d7f11769084f0368af795f59c692d2debbb4dad2eaaca05150',
                'rule_id': '50045a80bc2eb3e1c66c58f0a55acfc5e8db0f87e8b18bd8772a1361b20c1313',
                'rule_version': 'f5b8180b2b81602eaabd25d2e8ac3e8609321f3f5318d81d2d80c36fe4d8be93',
                'severity': 'd8fb260b8a62f9175181cdba1356bfbd3dab9167f0965c5e7586e2202c62bcc3',
                'source_presence': '31f6a55e225e04f5da96ef7f565969408d500a329be1bf37e463188763a5af16',
                'ts': 'bfc0e0328d7a2b9fb224bc2791da7a13f533d4b8f03819ad9f65e7609fac08e0'},
 'rule_cells': {'all_fields': '20a1f915ccb294a04c1d67b497c0b31d8bf186067fab3d1cd3ca7a2a232158da',
                'count': 18252,
                'detail': 'bbae80694d9fc180c7836342da979ab0d91f37ee5143312ceb103abb905d8d7f',
                'evaluated': '0d54ccc8c705e92e49ba35fa799cddbabda8acc1df656c1fb2a43e3e9761416a',
                'matched': 'c8b1f90b1c4007b2fc6288d2be106dc78ec44426696421cc3a25525e4168f7d2',
                'partition': '6fed6d30078fb22922b265544eb4155d422474b17f432f1a08ef411ddacdefb7',
                'rule_id': '10c0cc056dbbc99dc8c6a5a790c54e5242b1236cb63fd919eb8fde0090aa19b3',
                'rule_version': '079694f2aec852eb4133858c98d13051fb9b01574da64a91c702325b8d94f953',
                'state': '4572ef37f568d25fe187a0b2b922337be74f55f9406b0f01970ac23048754f78',
                'target': 'b28323b5b8624bb63846a455929f49c23bff677df713eb2991f93ecaf29e2756'}}
GOLDEN_NORMALIZED = {'arkime_sessions3-x': '45fd587022c97c90b1051e767517c87b20caf5ca9198ffe9abf83bb769a265bc',
 'arkime_sessions3-x+boots': '45fd587022c97c90b1051e767517c87b20caf5ca9198ffe9abf83bb769a265bc',
 'romulus-host-x': 'e14b5c171b2ba2daa659788340856089cab60624e5e1c584462644e10d758476',
 'romulus-host-x+boots': 'fc9d7c82c457d4f925b24b4e42b95b5a7e1b9b8f65d44dc190cf06c412272c9f',
 'romulus-network-x': 'ecebf6d14d297059cc509e8cacbf237a2e512e29462943222bc054d288cc2325',
 'romulus-network-x+boots': 'ecebf6d14d297059cc509e8cacbf237a2e512e29462943222bc054d288cc2325'}
GOLDEN_PIVOT = {'arkime_sessions3-x:-': '8f99efcb15167c4b8c5e23a6d942bdefd4a716dc7512a3450b4a665cd374b0bb',
 'arkime_sessions3-x:auth,net_socket,process_exec': '8f99efcb15167c4b8c5e23a6d942bdefd4a716dc7512a3450b4a665cd374b0bb',
 'arkime_sessions3-x:net_flow': '8f99efcb15167c4b8c5e23a6d942bdefd4a716dc7512a3450b4a665cd374b0bb',
 'arkime_sessions3-x:net_socket': '8f99efcb15167c4b8c5e23a6d942bdefd4a716dc7512a3450b4a665cd374b0bb',
 'arkime_sessions3-x:process_exec': '8f99efcb15167c4b8c5e23a6d942bdefd4a716dc7512a3450b4a665cd374b0bb',
 'romulus-host-x:-': '436da42a4b3488b16b150d3f59c982382ba8a68f2c58aefbc0f1eaa84fa61fe6',
 'romulus-host-x:auth,net_socket,process_exec': '436da42a4b3488b16b150d3f59c982382ba8a68f2c58aefbc0f1eaa84fa61fe6',
 'romulus-host-x:net_flow': '436da42a4b3488b16b150d3f59c982382ba8a68f2c58aefbc0f1eaa84fa61fe6',
 'romulus-host-x:net_socket': 'cd8f3ba6d1224c53afef7f07ed50229b78ec5e2c476312a2c05626df505cb595',
 'romulus-host-x:process_exec': 'c2631652077465825707c764f51d7b2ca8e6127ed14ea7ec769d41b80000aa68',
 'romulus-network-x:-': '6efca578694e933a6871870f1f06cdaa5afb177cac14b365d81261b0ab43ec92',
 'romulus-network-x:auth,net_socket,process_exec': '9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6',
 'romulus-network-x:net_flow': 'a2fa0ca1052f6ecf66953fd4eaf13cba4e68c344897e5fd9c66124d207a04638',
 'romulus-network-x:net_socket': '9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6',
 'romulus-network-x:process_exec': '9e505ce98b1b1f339349e89f9e2e58082d9066b316aa4aa97b727de0423759c6'}
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


@pytest.fixture(scope="module")
def stacks(docs, tmp_path_factory):
    """The stack as a hunt runs it (ranked) and seeded by the rule estimate alone, over the same documents."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        tf.patched_sizes(monkeypatch)
        ranked = tf.run_stack(tmp_path_factory.mktemp("ranked"), docs=docs)
        by_rule_estimate = tf.run_stack(tmp_path_factory.mktemp("rule-estimate"), docs=docs, rank=False)
    return ranked, by_rule_estimate


def test_the_sweep_and_expansion_stack_reproduces_the_captured_result(stacks):
    snapshot = stacks[0]
    # the scenario is not vacuous: findings, splits, capped fetches, expansion links and a manifest
    assert {c["lane"] for c in snapshot["candidates"]} >= {"high", "lead"}
    assert sum(c["state"] == "split" for c in snapshot["rule_cells"]) > 100
    assert sum(t["state"] == "split" for t in snapshot["tasks"]) >= 2
    assert sum(link["status"] == "complete" for link in snapshot["links"]) > 10
    assert snapshot["manifest"]["findings"]
    _assert_every_citation_resolves_with_raw(snapshot)
    assert tf.deterministic_golden_digests(snapshot) == GOLDEN_STACK
    assert _non_baseline_semantic_digests(snapshot) == GOLDEN_NON_BASELINE_SEMANTICS
    assert all(finding.get("rank") is not None for finding in snapshot["manifest"]["findings"])
    assert snapshot["manifest"]["ranking"]["status"] == "complete"


def test_the_stack_seeded_by_the_rule_estimate_is_unchanged_by_ranking(stacks):
    """Without the ranking passes, the stack reproduces the result captured before evidence ranking existed."""
    snapshot = stacks[1]
    # only rule versions moved its candidates at this evidence epoch (819d72ca... at epoch 17)
    assert tf.deterministic_golden_digests(tf.with_prior_versions(snapshot))["candidates"] == (
        "93593433453100bcd7a4e3a24a40ac1a34bdbeec399cda01eb4b6171c37bb7f5")
    assert tf.deterministic_golden_digests(snapshot) == GOLDEN_STACK_BY_RULE_ESTIMATE
    assert _non_baseline_semantic_digests(snapshot) == GOLDEN_NON_BASELINE_SEMANTICS_BY_RULE_ESTIMATE


def test_ranked_seeds_never_take_budget_from_the_rule_estimates_anchors(stacks):
    """Every anchor the rule estimate seeds fetches exactly the links it fetched without ranking, keeps its status
    and reasons, and every finding found without ranking is still found; the extra seeds spend only what is left."""
    ranked, by_rule_estimate = stacks
    earlier = {row["id"]: row for row in by_rule_estimate["anchors"]}
    now = {row["id"]: row for row in ranked["anchors"]}
    assert earlier and set(earlier) <= set(now)
    for anchor_id, row in earlier.items():
        assert (now[anchor_id]["status"], now[anchor_id]["reasons"]) == (row["status"], row["reasons"])

    def links(snapshot):
        return sorted(json.dumps(link, sort_keys=True, default=str) for link in snapshot["links"]
                      if link["anchor_id"] in earlier)

    assert links(ranked) == links(by_rule_estimate)
    assert {row["id"] for row in by_rule_estimate["candidates"]} <= {row["id"] for row in ranked["candidates"]}
    # extra seeds come only from entities with a confirmed finding; this scenario's Reported leads sit on entities
    # reported for their breadth alone, so the ranked stack anchors exactly the rule estimate's seeds
    extra = [row for row in ranked["anchors"] if row["id"] not in earlier]
    assert all(row["lane"] == "lead" and row["depth"] == 0 for row in extra)
    assert ranked["expansion"]["source_queries"] <= 180


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
