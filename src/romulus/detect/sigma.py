"""Pinned local Sigma rules over typed evidence, with indexed batch routing."""
from __future__ import annotations

from collections import defaultdict

from romulus.content.sigma_parser import evaluate_ast
from romulus.detect.base import Match, Playbook, argv_incomplete, pf


def _class(event):
    return (str(event.get('event.channel', '')).casefold(),
            str(event.get('event.provider', '')).casefold(), str(event.get('event.code', '')))


class SigmaRule(Playbook):
    """One immutable imported AST, activated and pinned by the local content service."""
    kind = 'direct'
    assures_negative = False
    positive_only_reason = ('Local Sigma predicates interpret recorded fields; a no-match does not establish '
                            'that the behavior did not occur.')
    required_fields = ()
    attack_exempt = 'Imported local Sigma tags are validated against the pinned ATT&CK bundle.'

    def __init__(self, row):
        super().__init__()
        self.metadata = row
        self.id = 'sigma.'+row['id']
        self.title = row['title']
        self.version = '1+'+row['digest']
        self.ast = row['ast']
        mapping = row['mapping']
        self.families = tuple(mapping.get('families', ()))
        self.os_families = tuple(mapping.get('os_families', ('linux', 'windows', 'unknown')))
        self.windows_event_classes = tuple(tuple(item) for item in mapping.get('windows_event_classes', ()))
        self._classes = frozenset((str(c).casefold(), str(p).casefold(), str(i))
                                  for c, p, i in self.windows_event_classes)
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

    def accepts(self, event):
        return (event.family in self.families and self.event_in_os_scope(event)
                and (not self._classes or _class(event) in self._classes))

    def scope_partition(self, events):
        return [event for event in events if self.accepts(event)]

    def consume(self, events):
        self._batch_argument_gap = False
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
            matched, fields = evaluate_ast(self.ast, event)
            if not matched:
                continue
            provenance = self.metadata
            names = list(dict.fromkeys(fields))
            # Scope identity is evidence even for a condition asserting an explicit field absence.
            names.extend(name for name in ('event.code', 'event.channel', 'event.provider')
                         if event.has(name) and name not in names)
            yield Match(self.id,
                f"The record matched the Sigma rule {self.title} ({provenance['upstream_path']}@"
                f"{provenance['upstream_commit']}).", 'aggregate_observation', [event], [pf(event, name) for name in names],
                event.ts, self.severity, self.lane, 'medium', event.entities(), notes=[
                    (f"Author: {provenance['author']}; upstream: {provenance['upstream']}; Sigma level: "
                     f"{provenance['level']}; AST/mapping digest: {provenance['digest']}."),
                    self.positive_only_reason,
                    *([f"Lead lane override: {provenance['activation_reason']}"] if self.lane == 'high' else [])])


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
            return [event for family in rule.families for key in rule._classes
                    for event in self._classes.get((family, *key), ()) if rule.event_in_os_scope(event)]
        return [event for family in rule.families for event in self._families.get(family, ())
                if rule.event_in_os_scope(event)]
