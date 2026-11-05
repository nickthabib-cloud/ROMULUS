"""Bounded observed Zeek joins and lease-backed host hypotheses."""
from __future__ import annotations

from datetime import datetime, timedelta

from romulus.evidence.zeek_catalog import ZEEK_LOGS
from romulus.hunt.zeek_context import FILE_FIELDS, UID_FIELDS
from romulus.hunt.zeek_sources import key_intents

ZEEK_LINK_TYPES = frozenset({'zeek_uid', 'zeek_file', 'certificate', 'address_host'})
MAX_ROWS = 10000
MAX_KEYS = 1000
MAX_QUERIES = 128


def values(event, fields):
    result = set()
    for field in fields:
        value = event.get(field)
        if value is not None:
            result.update(str(item) for item in (value if isinstance(value, list) else [value]) if item)
    return result


def event_keys(event, kind):
    if event.get('observer.product') != 'zeek':
        return []
    sensor = event.get('observer.name')
    if not sensor:
        return []
    if kind == 'zeek_uid':
        return [{'sensor': sensor, 'uid': uid} for uid in sorted(values(event, UID_FIELDS))]
    if kind == 'zeek_file':
        return [{'sensor': sensor, 'fuid': fuid} for fuid in sorted(values(event, FILE_FIELDS))]
    if kind == 'certificate':
        chain = event.get('tls.server.cert_chain_fps') or []
        return [{'sensor': sensor, 'fingerprint': chain[0]}] if isinstance(chain, list) and chain else []
    if kind == 'address_host':
        return [{'sensor': sensor, 'ip': value} for field in ('source.ip', 'destination.ip')
                if (value := event.get(field))]
    return []


def anchor_key(anchor, kind):
    return anchor.link_key or next((key for event in anchor.events for key in event_keys(event, kind)), {})


def _logs(names=None):
    return [log for log in ZEEK_LOGS if names is None or log.name in names]


class ZeekLink:
    """One dependent join, sharing finite row/key/query budgets across every hop and target."""
    def __init__(self, fetcher, anchor, kind, window, query_cap):
        self.fetcher, self.executor, self.anchor = fetcher, fetcher.executor, anchor
        self.kind, self.window = kind, window
        self.key = anchor_key(anchor, kind)
        self.sensor = self.key.get('sensor')
        self.fetch_key = fetcher._fetch_key(anchor, kind, window, self.key)
        self.start_queries = getattr(self.executor, 'source_queries', 0)
        self.query_cap = min(MAX_QUERIES, query_cap) if query_cap is not None else MAX_QUERIES
        self.rows = 0
        self.keys = set()
        self.events = {}
        self.batches = []
        self.reasons = []
        self.coverage = []
        self.task_ids = []
        self.duration = 0
        self.partial = False

    def unresolved(self, reason):
        self.partial = True
        if reason not in self.reasons:
            self.reasons.append(reason)

    def query(self, logs, fields, keys, window, retain, *, intents=None, host=False):
        keys = set(keys)
        additions = keys-self.keys
        if len(self.keys)+len(additions) > MAX_KEYS:
            self.unresolved(f'Zeek link hop-key limit {MAX_KEYS} reached; remaining joins unresolved')
            keys = set(sorted(keys)[:max(0, MAX_KEYS-len(self.keys))])
        self.keys.update(keys)
        remaining = MAX_ROWS-self.rows
        queries = self.query_cap-(getattr(self.executor, 'source_queries', 0)-self.start_queries)
        if remaining <= 0 or queries <= 0:
            self.unresolved(f'Zeek link shared row/query limit reached ({MAX_ROWS} rows, {self.query_cap} queries)')
            return []
        if intents is None:
            plan=key_intents(self.executor.contracts,logs,self.sensor,fields,keys,window,limit=remaining)
            intents=plan.intents
            for reason in plan.reasons:
                self.unresolved(reason)
        if not intents:
            self.unresolved('Zeek link source key or sensor is not searchable; join unresolved')
            return []
        batch = self.executor.fetch_intents(self.anchor.finding_id, self.fetch_key, intents,
            lambda event: (host or event.get('observer.name') == self.sensor) and retain(event),
            anchor_ts=self.anchor.ts, query_cap=queries, persist=False, max_total_records=remaining)
        self.batches.append(batch)
        self.rows += sum(cell.returned or 0 for cell in batch.coverage) or len(batch.events)
        self.partial |= batch.status != 'complete'
        self.reasons.extend(reason for reason in batch.reasons if reason not in self.reasons)
        self.coverage.extend(batch.coverage)
        self.task_ids.extend(batch.task_ids)
        self.duration += batch.duration_ms
        kept = batch.events[:max(0, MAX_ROWS-len(self.events))]
        if self.rows >= MAX_ROWS or len(kept) != len(batch.events):
            self.unresolved(f'Zeek link shared fetched-row limit {MAX_ROWS} reached; remaining joins unresolved')
        self.events.update((event.id, event) for event in kept)
        return kept

    def span(self, conns):
        from romulus.hunt.links import LinkWindow
        starts, ends = [], []
        for event in conns:
            if event.get('zeek.log') != 'conn':
                continue
            start, end = event.get('flow.start'), event.get('flow.end')
            if start and end:
                starts.append(datetime.fromisoformat(start))
                ends.append(datetime.fromisoformat(end))
        if not starts:
            self.unresolved('connection span not in scope; bounded 24 h UID lookup used')
            return LinkWindow(label=self.window.label, start=self.anchor.ts-timedelta(hours=24),
                              end=self.anchor.ts+timedelta(minutes=5))
        # Analyzer/file rows can be written after close; one minute before start
        # tolerates modest timestamp skew and five after end permits log-write lag.
        return LinkWindow(label=self.window.label, start=min(starts)-timedelta(minutes=1),
                          end=max(ends)+timedelta(minutes=5))

    def run(self):
        from romulus.hunt.links import LinkResult, LinkWindow
        if not self.sensor:
            self.unresolved('required Zeek sensor-scoped key unavailable')
        elif self.kind == 'certificate':
            fingerprint = self.key.get('fingerprint')
            if fingerprint:
                self.window = LinkWindow(label=self.window.label, start=self.anchor.ts-timedelta(days=30),
                                         end=self.anchor.ts+timedelta(minutes=5))
                self.query(_logs({'x509'}), ('x509.fingerprint',), [fingerprint, fingerprint.upper()], self.window,
                           lambda event: event.get('zeek.log') == 'x509'
                           and event.get('x509.fingerprint') == fingerprint.lower())
            if not self.events:
                self.unresolved('certificate details not in scope')
        elif self.kind == 'zeek_uid':
            uid = self.key.get('uid')
            if uid:
                conns = [event for event in self.anchor.events if event.get('zeek.log') == 'conn'
                         and uid in values(event, UID_FIELDS)]
                if not conns:
                    lookback = LinkWindow(label=self.window.label, start=self.anchor.ts-timedelta(hours=24),
                                          end=self.anchor.ts+timedelta(minutes=5))
                    conns = self.query(_logs({'conn'}), UID_FIELDS, [uid], lookback,
                                       lambda event: event.get('zeek.log') == 'conn' and uid in values(event, UID_FIELDS))
                self.window = self.span(conns)
                self.query(_logs(), UID_FIELDS, [uid], self.window, lambda event: uid in values(event, UID_FIELDS))
        elif self.kind == 'zeek_file':
            fuid = self.key.get('fuid')
            if fuid:
                lookup = LinkWindow(label=self.window.label, start=self.anchor.ts-timedelta(hours=24),
                                    end=self.anchor.ts+timedelta(minutes=5))
                files = self.query(_logs({'files'}), FILE_FIELDS, [fuid], lookup,
                                   lambda event: event.get('zeek.log') == 'files' and fuid in values(event, FILE_FIELDS))
                files += [event for event in self.anchor.events if event.get('zeek.log') == 'files'
                          and fuid in values(event, FILE_FIELDS)]
                uids = set().union(*(values(event, UID_FIELDS) for event in files))
                conns = self.query(_logs({'conn'}), UID_FIELDS, uids, lookup,
                                   lambda event: event.get('zeek.log') == 'conn' and bool(values(event, UID_FIELDS) & uids)) if uids else []
                self.window = self.span(conns)
                self.query(_logs({'files', 'pe', 'x509'}), FILE_FIELDS, [fuid], self.window,
                           lambda event: fuid in values(event, FILE_FIELDS))
                if not files:
                    self.unresolved('carrying file records not in scope')
                if not uids:
                    self.unresolved('carrying connection identities not in scope')
        elif self.kind == 'address_host':
            from romulus.evidence.typed import NETWORK_OBSERVER_FAMILIES
            from romulus.hunt.links import _first_label
            ip = self.key.get('ip')
            self.window = LinkWindow(label=self.window.label, start=self.anchor.ts-timedelta(days=7),
                                     end=self.anchor.ts+timedelta(microseconds=1))
            def active(event):
                duration = event.get('dhcp.lease_s')
                try:
                    return (event.get('dhcp.assigned_ip') == ip and isinstance(duration, (int, float)) and duration > 0
                            and event.ts <= self.anchor.ts < event.ts+timedelta(seconds=duration))
                except OverflowError:
                    self.unresolved('DHCP lease duration cannot establish a representable interval; host unresolved')
                    return False
            leases = self.query(_logs({'dhcp'}), ('dhcp.assigned_ip',), [ip] if ip else [], self.window, active)
            identities = {(str(event.get('dhcp.hostname') or '').strip().rstrip('.').casefold(),
                           str(event.get('dhcp.client_mac') or '')) for event in leases}
            self.reasons.append('Address-to-host relation is a hypothesis supported by the cited DHCP lease; '
                                'lease interval must cover the anchor time')
            if not identities:
                self.unresolved(f'no covering DHCP lease in the bounded scope for {ip}; host unresolved')
            elif len(identities) > 1:
                labels = ', '.join(f'{name or "unnamed host"} ({mac or "unknown MAC"})' for name, mac in sorted(identities))
                self.unresolved(f'conflicting overlapping DHCP leases for {ip}: {labels}; host unresolved')
            else:
                name, mac = next(iter(identities))
                if not name or not mac:
                    self.unresolved(f'DHCP lease for {ip} lacks hostname or MAC; host unresolved')
                else:
                    native = {host for contract in self.executor.contracts.values() if contract.role == 'host'
                              for host in contract.hosts if _first_label(host) == _first_label(name)}
                    if len(native) > 1:
                        self.unresolved(f'DHCP hostname {name} matches conflicting host telemetry names: {sorted(native)}')
                    else:
                        host = next(iter(native), name)
                        intents = self.fetcher._host_intents(self.window, None, host)
                        witnesses = self.query([], (), [host], self.window,
                            lambda event: event.family not in NETWORK_OBSERVER_FAMILIES
                            and event.host is not None and _first_label(event.host) == _first_label(name),
                            intents=intents, host=True)
                        if not witnesses:
                            self.unresolved(f'DHCP hostname {name} matches no host-telemetry host in scope')
        else:
            self.unresolved('required Zeek join is not available')
        linked = sorted((event for event in self.events.values() if event.id not in self.anchor.event_ids),
                        key=lambda event: (event.ts, event.id))
        for batch in self.batches:
            ids = {event.id for event in batch.events}
            self.executor.save_batch_selection(batch, [event for event in linked if event.id in ids])
        self.reasons.append(f'searched {self.window.start.isoformat()}–{self.window.end.isoformat()}; '
                            + ('30 day certificate lookback; older deduplicated details may be out of scope'
                               if self.kind == 'certificate' else '7 day DHCP lease lookback' if self.kind == 'address_host'
                               else 'connection span with -1 minute/+5 minute log-write slack'))
        return LinkResult(id='link-'+self.fetch_key[:20], anchor_id=self.anchor.finding_id,
            link_type=self.kind, window=self.window, strength='inferred' if self.kind == 'address_host' else 'observed',
            key=self.key, status='partial' if self.partial else 'complete', event_ids=[event.id for event in linked],
            evidence_ids=sorted(set(self.anchor.event_ids+[event.id for event in linked])),
            reasons=self.reasons, task_ids=sorted(set(self.task_ids)), coverage=self.coverage,
            duration_ms=self.duration, query_spend=getattr(self.executor, 'source_queries', 0)-self.start_queries)
