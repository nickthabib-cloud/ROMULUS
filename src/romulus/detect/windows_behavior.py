"""Fleet behavior findings backed by the normal bounded group and citation stores."""
from __future__ import annotations

from romulus.detect.windows_events import WindowsEventRule


class BehaviorFleetRule(WindowsEventRule):
    """The first observation and subsequent fleet revisions share one finding key.

    The inherited disk-backed stores bound in-memory membership and held citations.
    Source cardinality also uses that store, rather than a per-shape Python set.
    """
    count_source_ips = False

    def fleet_eligible(self, event, hit):
        return True

    def _offer_group_example(self, group, event, hit, *, new_host):
        return (new_host or not self.fleet_eligible(event, hit)) and group.examples.offer(event)


    def _fold(self, event, hit, out):
        if not self.fleet_eligible(event, hit):
            shape, role = super()._fold(event, hit, out)
            group = self.groups.get(shape) if shape else None
            if group is not None:
                group.behavior_fleet = False
                self.groups.put(shape, group)
            return shape, role
        shape = self._shape(event, hit)
        ip = event.get('source.ip')
        if self.count_source_ips and ip:
            key = ('source_ip', shape, ip)
            if self.members_store.get(key) is None:
                if self.members_store.put(key, 1):
                    count_key = ('source_ip_count', shape)
                    count = self.members_store.get(count_key) or 0
                    if not self.members_store.put(count_key, count + 1):
                        self.note_limit('fleet_source_ips', 'Distinct source IP count could not be fully retained.')
                else:
                    self.note_limit('fleet_source_ips', 'Distinct source IP count could not be fully retained.')
        start = len(out)
        shape, role = super()._fold(event, hit, out)
        if shape is None:
            return shape, role
        group = self.groups.get(shape)
        if group is None:
            return shape, role
        if group.records == 1:
            for match in out[start:]:
                match.group_key = f'{self.id}|fleet|{shape}'
                match.fleet_hosts = ((event.host, event.id),)
                match.fleet_host_count = group.hosts
                match.fleet_hosts_complete = False
        elif role == 'own':
            # A newly observed host revises the fleet finding immediately.
            merged = self._fleet_match(shape, group, final=False)
            if merged is not None:
                merged.revision_reason = 'a newly observed host revised the running fleet membership and count'
                merged.fleet_hosts = ((event.host, event.id),)
                merged.fleet_hosts_complete = False
                out[start:] = [merged]
                group.emitted_records = group.records
                self.groups.put(shape, group)
        return shape, role

    def _fleet_match(self, shape, group, *, final):
        result = super()._fleet_match(shape, group, final=final)
        if result is not None and getattr(group, 'behavior_fleet', True):
            result.claim = result.claim.replace(
                "Each host's first record keeps its own finding.",
                'The first observation was published immediately; members revise this fleet finding.',
            ).replace('each host\'s first record keeps its own finding',
                      'the first observation was published immediately').replace(
                          ' and remains retrievable',
                          '; this fleet finding revises that observation in place').replace(
                          'recurred as the same shape on a host already reported for it:',
                          'was observed as the same behavior class:')
            if self.count_source_ips:
                count = self.members_store.peek(('source_ip_count', shape)) or 0
                qualifier = 'At least ' if 'fleet_source_ips' in self.limits else ''
                result.claim += f' {qualifier}{count} distinct source IP address(es) were recorded.'
            if group.records > len(result.events):
                result.notes.append(f'Citation coverage is partial: {len(result.events)} of {group.records} '
                                    'counted event records are cited as bounded examples and time boundaries; '
                                    'the total record count includes the uncited members.')
            result.notes = [note.replace('new hosts keep their own findings',
                                        'new hosts revise this fleet finding immediately') for note in result.notes]
        return result
