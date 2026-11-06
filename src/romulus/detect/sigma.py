"""Pinned local Sigma rules over typed evidence, with bounded grouped publication."""
from __future__ import annotations

import hashlib
import json
import ntpath
import posixpath
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

from romulus.content.sigma_parser import evaluate_ast_detail
from romulus.detect.base import LANES, Match, Playbook, argv_incomplete, pf
from romulus.detect.bounded import HeldExamples, KeyedStore
from romulus.detect.citing import BoundStage, Ends, bound_note, citation_group, cite_extra, cited_phrase


def _class(event):
    return (str(event.get('event.channel', '')).casefold(),
            str(event.get('event.provider', '')).casefold(), str(event.get('event.code', '')))


def _encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), default=str)


@dataclass
class _Fold:
    host: str | None
    count: int = 0
    lane: str = 'context'
    ends: Ends = field(default_factory=Ends)
    examples: HeldExamples = field(default_factory=lambda: HeldExamples(2))
    commands: HeldExamples = field(default_factory=lambda: HeldExamples(16))
    command_keys: set[str] = field(default_factory=set)
    published: bool = False
    groups: int = 0
    exact: bool = True


class SigmaRule(Playbook):
    """One immutable imported AST, activated and pinned by the local content service."""
    kind = 'aggregate'
    staged = True
    needs_live_loader = True
    state_slice = 'strong'
    assures_negative = False
    claim_type = 'aggregate_observation'
    positive_only_reason = ('Local Sigma predicates interpret recorded fields; a no-match does not establish '
                            'that the behavior did not occur.')
    required_fields = ()
    attack_exempt = 'Imported local Sigma tags are validated against the pinned ATT&CK bundle.'
    # A rule can expose 1,000 separately actionable behaviors plus a summary. This bounds analyst-facing rows
    # and expansion anchors independently of a hunt's record or host count; all further positives remain counted.
    PUBLICATION_LIMIT = 1_000
    HOT = 512
    TRIM_EVERY = 512
    EXAMPLE_LIMIT = 20

    def __init__(self, row):
        super().__init__()
        self.metadata = row
        self.id = 'sigma.'+row['id']
        self.title = row['title']
        self.version = '2+'+row['digest']
        self.ast = row['ast']
        mapping = row['mapping']
        self.category = mapping.get('category', '')
        self.families = tuple(mapping.get('families', ()))
        self.os_families = tuple(mapping.get('os_families', ('linux', 'windows', 'unknown')))
        self.windows_event_classes = tuple(tuple(item) for item in mapping.get('windows_event_classes', ()))
        self._classes = frozenset((str(c).casefold(), str(p).casefold(), str(i))
                                  for c, p, i in self.windows_event_classes)
        self.anchor_class = ('network_observation' if self.category in
            {'network_connection', 'dns', 'dns_query', 'proxy', 'firewall'} else 'execution')
        self.lane = row['lane']
        self.severity = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low',
                         'informational': 'info'}.get(row['level'], 'medium')
        self.status = row['status']
        self.attack = tuple(tag.removeprefix('attack.').upper() for tag in row['tags']
                            if tag.casefold().startswith('attack.t') and tag[8:9].isdigit())
        self.card = {'telemetry': ', '.join(self.families),
                     'behavior': 'Matched imported Sigma predicates; '+row['upstream_path']+'@'+row['upstream_commit'],
                     'fidelity': self.positive_only_reason,
                     'provenance': {key: row[key] for key in ('author', 'upstream', 'upstream_path', 'upstream_commit')}}
        self.match_evaluations = 0
        self._batch_argument_gap = False
        self.groups = KeyedStore(self, 'sigma_groups', self.HOT)
        self.delivered = KeyedStore(self, 'sigma_delivered', self.HOT)
        self.overflow_keys = KeyedStore(self, 'sigma_overflow_keys', self.HOT)
        self.overflow = _Fold(None)
        self.bounds = BoundStage()
        self._pending = []
        self._fresh = []
        self.load = lambda ids: []
        self._detailed_groups = 0
        self._overflow_key = 'sigma-overflow:'+row['id']
        self._batch_unknown = {}

    def accepts(self, event):
        return (event.family in self.families and self.event_in_os_scope(event)
                and (not self._classes or _class(event) in self._classes))

    def scope_partition(self, events):
        return [event for event in events if self.accepts(event)]

    def _key(self, event):
        category = self.category
        if category == 'process_creation':
            values = [(name, event.get(name)) for name in ('process.executable', 'process.parent.executable')]
        elif category == 'network_connection':
            values = [(name, event.get(name)) for name in
                      ('destination.ip', 'destination.hostname', 'destination.address', 'destination.domain',
                       'destination.port')]
        elif category in {'dns', 'dns_query'}:
            names = event.get('dns.question.names')
            query = event.get('dns.question.name')
            values = [('dns.question.name', query or (sorted(names) if isinstance(names, list) else None))]
        elif category.startswith(('file_', 'registry_')) or category == 'create_stream_hash':
            name = 'registry.path' if category.startswith('registry_') else 'file.path'
            value = event.get(name)
            if isinstance(value, str):
                path = ntpath if '\\' in value else posixpath
                values = [(name+'.directory', path.dirname(value)), (name+'.name', path.basename(value))]
            else:
                values = [(name, value)]
        else:
            values = []
        identity = [self.id, event.host, category, values]
        return 'sigma-fold:'+hashlib.sha256(_encoded(identity).encode()).hexdigest()

    def _remember(self, key, state, event):
        state.count += 1
        if getattr(self, '_unaggregated_reason', ''):
            state.exact = False
        if LANES.index(self.lane) < LANES.index(state.lane):
            state.lane = self.lane
        self.bounds.offer_at(key, state.ends, event)
        if state.examples.offer(event):
            self._pending.append(event)
            self._fresh.append(state.examples)
        command = event.get('process.command_line')
        if command is None:
            command = event.get('process.argv')
        if command is not None and len(state.command_keys) < state.commands.limit:
            digest = hashlib.sha256(_encoded(command).encode()).hexdigest()
            if digest not in state.command_keys:
                state.command_keys.add(digest)
                if state.commands.offer(event):
                    self._pending.append(event)
                    self._fresh.append(state.commands)

    def _coverage_budget(self):
        if not self.overflow.count:
            return
        text = (f'Sigma publication budget: {self.PUBLICATION_LIMIT} detailed behavior groups per rule; '
                f'{self.overflow.groups} additional group(s) containing {self.overflow.count} matching record(s) '
                'withheld as separate candidates and retained in one bounded positive summary.')
        if not self.overflow.exact:
            text += ' Unique identities could not all be retained; the summary counts delivered matches.'
        self.note_limit('sigma_publication_budget', text)
        self.limits['sigma_publication_budget'].text = text

    def partition_coverage_notes(self):
        notes = [f'{reason}: {count} record comparison(s) undecidable.' for reason, count in
                 sorted(self._batch_unknown.items())]
        if self.overflow.count:
            notes.append(self.limits['sigma_publication_budget'].text)
        return notes

    def consume(self, events):
        self._batch_argument_gap = False
        self._batch_unknown = {}
        changed = {}
        kept = 0
        for event in events:
            if not self.accepts(event):
                continue
            if not self._events_pre_scoped:
                self.os_applicable += 1
            if argv_incomplete(event):
                self._batch_argument_gap = True
                self.note_limit('incomplete_arguments', 'Recorded arguments are incomplete; predicates on intact '
                                'typed fields are evaluated, command-line comparisons remain unknown.')
            self.evaluated += 1
            self.match_evaluations += 1
            matched, _fields, unknown = evaluate_ast_detail(self.ast, event)
            for reason in unknown:
                self._batch_unknown[reason] = self._batch_unknown.get(reason, 0)+1
                self.note_limit('sigma_undecidable', 'Sigma comparisons are undecidable on delivered typed fields.')
            if unknown:
                self.missing_required += 1
            if not matched or self.delivered.get(event.id) is not None:
                continue
            remembered = self.delivered.put(event.id, True)
            key = self._key(event)
            state = self.groups.get(key)
            if state is None and self._detailed_groups < self.PUBLICATION_LIMIT and remembered:
                state = _Fold(event.host)
                if self.groups.put(key, state):
                    self._detailed_groups += 1
                else:
                    state = None
            if state is None:
                if self.overflow_keys.get(key) is None:
                    if self.overflow_keys.put(key, True):
                        self.overflow.groups += 1
                    else:
                        self.overflow.exact = False
                state, key = self.overflow, self._overflow_key
                if not remembered:
                    state.exact = False
                    self.note_limit('sigma_delivery_identity', 'Matching delivery identities could not all be '
                                    'retained; positive summary counts deliveries rather than unique records.')
            self._remember(key, state, event)
            changed[key] = state
            kept += 1
            if kept % self.TRIM_EVERY == 0:
                self.delivered.trim()
                self.overflow_keys.trim()
        self.delivered.trim()
        self.overflow_keys.trim()
        self._coverage_budget()
        output = []
        for key, state in changed.items():
            out = []
            with citation_group(self, out, key, state):
                out.append(self._finding(key, state))
            state.published = True
            output.extend(out)
        return output

    def consume_unaggregated(self, events, reason):
        """Keep record predicates visible when cumulative connection identity is unavailable."""
        self.note_limit('source_identity', reason+'; Sigma summaries count matching deliveries, not unique connections.')
        self._unaggregated_reason = reason
        try:
            return self.consume_scoped_partition(events)
        finally:
            self._unaggregated_reason = ''

    def drain_staged(self):
        out, self._pending = self._pending+self.bounds.drain(), []
        for examples in self._fresh:
            examples.staged()
        self._fresh = []
        self.groups.trim()
        self.delivered.trim()
        self.overflow_keys.trim()
        return out

    def drain_bounds(self):
        return self.bounds.last

    def retained_events(self):
        return []

    def _notes(self):
        provenance = self.metadata
        return [(f"Author: {provenance['author']}; upstream: {provenance['upstream']}; Sigma level: "
                 f"{provenance['level']}; source: {provenance['upstream_path']}@{provenance['upstream_commit']}; "
                 f"AST/mapping digest: {provenance['digest']}."),
                self.positive_only_reason,
                *([f"Lead lane override: {provenance['activation_reason']}"]
                  if provenance['activation_reason'] else [])]

    def _claim(self, state):
        provenance = self.metadata
        first, last = (datetime.fromtimestamp(bound[0], UTC).isoformat()
                       for bound in (state.ends.first, state.ends.last))
        subject = f'on {state.host}' if state.host is not None else 'across additional behavior groups'
        count = f'{state.count} record(s)' if state.exact else f'{state.count} matching delivery record(s)'
        claim = (f"{count} {subject} matched the Sigma rule {self.title} ({provenance['upstream_path']}@"
                 f"{provenance['upstream_commit']}) ({first} – {last}).")
        if state is self.overflow:
            claim += (f' This positive summary retains {state.groups} additional group(s) beyond the '
                      f'{self.PUBLICATION_LIMIT}-group publication budget; their separate candidates are withheld.')
        return claim

    def _finish(self, key, state, match):
        match.group_key = key
        match.severity = self.severity
        match.proposed_lane = state.lane
        match.notes = self._notes()+match.notes
        match.revision_reason = 'Sigma behavior-group count, interval and bounded examples updated'
        match.bounded_revision = True
        match.aggregate_summary = {'peak': state.count, 'episodes': 1, 'count': state.count,
            'first': state.ends.first[0], 'last': state.ends.last[0]}
        return match

    def _finding(self, key, state):
        examples = state.examples.events(self.load)+state.commands.events(self.load)
        known = {event.id: event for event in examples}
        for side in (0, 1):
            pending = self.bounds.pending.get((key, side))
            if pending:
                known[pending[0].id] = pending[0]
        def load(ids):
            missing = [identity for identity in ids if identity not in known]
            found = {event.id: event for event in self.load(missing)} if missing else {}
            return [known.get(identity) or found[identity] for identity in ids
                    if identity in known or identity in found]
        events, missing, context = cite_extra(load, load, state.ends, list(dict.fromkeys(
            event.id for event in examples)))
        predicates = []
        for event in events:
            matched, fields, _unknown = evaluate_ast_detail(self.ast, event)
            names = list(dict.fromkeys(fields)) if matched else []
            names.extend(name for name in ('event.code', 'event.channel', 'event.provider')
                         if event.has(name) and name not in names)
            predicates.extend(pf(event, name) for name in names if event.has(name))
        entities = list(dict.fromkeys(entity for event in events for entity in event.entities()))
        match = Match(self.id, self._claim(state), self.claim_type, events, predicates,
            datetime.fromtimestamp(state.ends.first[0], UTC), self.severity, state.lane, 'medium', entities,
            context_ids=context)
        match.claim += cited_phrase(len(events), state.count, not missing)+bound_note(missing, state.ends)
        return self._finish(key, state, match)

    def uncited_finding(self, key, state, match):
        match.claim = self._claim(state)+' Citation coverage is partial; the positive is retained from group state.'
        match.entities = [('host', state.host, 'host')] if state.host else []
        return self._finish(key, state, match)

    def finalize(self):
        # Every changed group publishes at its batch boundary. Finalize only supplies an as-yet unpublished state.
        for key, state in self.groups.items():
            if not state.published:
                out = []
                with citation_group(self, out, key, state):
                    out.append(self._finding(key, state))
                state.published = True
                yield from out
        if self.overflow.count and not self.overflow.published:
            out = []
            with citation_group(self, out, self._overflow_key, self.overflow):
                out.append(self._finding(self._overflow_key, self.overflow))
            self.overflow.published = True
            yield from out

    def finalize_fallback(self, reason):
        for key, state in self.groups.hot.items():
            if state.published:
                continue
            out = []
            with citation_group(self, out, key, state):
                out.append(self._finding(key, state))
            for match in out:
                match.notes.append(f'Group publication from memory only: disk state unavailable ({reason}).')
                yield match

    def release_state(self):
        self.groups.clear()
        self.delivered.clear()
        self.overflow_keys.clear()
        self.bounds.clear()
        self._pending = []
        self._fresh = []


class SigmaEventIndex:
    """Two references per delivered record; rules select family/class buckets."""
    def __init__(self, events):
        self._families = defaultdict(list)
        self._classes = defaultdict(list)
        self.records = 0
        for event in events:
            self._families[event.family].append(event)
            self._classes[(event.family, *_class(event))].append(event)
            self.records += 1
        self.buckets = len(self._classes)

    def for_rule(self, rule):
        if rule._classes:
            return [event for family in sorted(rule.families) for key in sorted(rule._classes)
                    for event in self._classes.get((family, *key), ()) if rule.event_in_os_scope(event)]
        return [event for family in sorted(rule.families) for event in self._families.get(family, ())
                if rule.event_in_os_scope(event)]
