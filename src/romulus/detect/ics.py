"""Positive ICS command observations; a packet is never proof of a physical process change."""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

from romulus.detect.base import Match, Playbook, pf
from romulus.detect.site_roles import address_member
from romulus.detect.windows_events import signal
from romulus.detect.windows_rows import row_key
from romulus.detect.windows_sequence_extensions import _Rows
from romulus.detect.zeek_lateral import ZeekBehaviorRule
from romulus.hunt.citations import compact_event, expand_event

# Five devices in ten minutes separates fan-out from a configured engineering tool's ordinary single-device
# query. Twenty distinct failed transactions in the same interval is repeated failure, rather than a lone bad
# request; either may still be a misconfigured poller. These are investigative thresholds, never DoS verdicts.
DISCOVERY_RECEIVERS = 5
EXCEPTION_REQUESTS = 20
WINDOW_SECONDS = 600
# This is the UDP stitching sensor-skew tolerance. Only different observers can share an exception;
# separate records from one observer remain separate even when a tool constantly reuses its transaction id.
SENSOR_COPY_SECONDS = 5
WRITE_PROTOCOLS = frozenset({'modbus','dnp3','s7comm','s7comm_plus','cip','bacnet'})
# Transaction identifiers are reused. Pair only the nearest request/response inside this protocol exchange
# horizon, scoped by observer, connection, protocol, function, unit and reversed packet endpoints.
PAIR_SECONDS = 600
_FIELDS = frozenset({'observer.product','observer.name','zeek.log','zeek.uid','source.ip','destination.ip',
    'ics.protocol','ics.function_code','ics.function_name','ics.op_class','ics.is_request','ics.exception',
    'ics.sender','ics.receiver','ics.transaction_id','ics.unit','ics.address','ics.quantity','ics.program_direction',
    'ics.status','ics.status_code','ics.error_class','ics.iin',
    'ics.request_observed','ics.request_function_name','conn.orig_h','conn.resp_h',
    'ics.is_orig','ics.endpoint_basis'})
_DOC = 'https://attack.mitre.org/matrices/ics/'


class _IcsRows(_Rows):
    schema = (*_Rows.schema,
        'CREATE TABLE IF NOT EXISTS ics_active(value TEXT PRIMARY KEY,ts REAL)',
        'CREATE INDEX IF NOT EXISTS ics_active_time ON ics_active(ts)',
        'CREATE TABLE IF NOT EXISTS ics_copies(k TEXT,id TEXT,ts REAL,PRIMARY KEY(k,id))',
        'CREATE INDEX IF NOT EXISTS ics_copies_time ON ics_copies(ts)',
        'CREATE TABLE IF NOT EXISTS ics_copy_sensors(k TEXT,id TEXT,sensor TEXT,PRIMARY KEY(k,id,sensor))',
        'CREATE TABLE IF NOT EXISTS ics_discovery(k TEXT,id TEXT,receiver TEXT,function TEXT,start REAL,end REAL,records INTEGER,first BLOB,last BLOB,PRIMARY KEY(k,id))',
        'CREATE INDEX IF NOT EXISTS ics_discovery_interval ON ics_discovery(k,receiver,function,start,end)',
        'CREATE TABLE IF NOT EXISTS ics_discovery_active(receiver TEXT PRIMARY KEY,copies INTEGER)')

    def compact_fields(self, key):
        return _FIELDS

    @staticmethod
    def _discovery_size(row):
        return sum(len(value) if isinstance(value,bytes) else len(str(value).encode()) for value in row)+256

    def discovery_put(self,key,event,peers):
        """Union [request time, time+window] intervals per device/function, including late input.

        At a window endpoint t a device contributes iff its union contains t. Coalescing overlapping
        intervals therefore preserves every qualifying sliding window without retaining every query.
        Disjoint history stays on disk; a row retains a count and bounded first/last native witnesses.
        """
        store=self.store()
        receiver=peers[1]
        function=row_key(event.get('ics.function_code'),event.get('ics.function_name'))
        start=event.ts.timestamp()
        end=start+WINDOW_SECONDS
        compact=event.model_copy(update={'fields':{name:fact for name,fact in event.fields.items() if name in _FIELDS}})
        first=last=compact_event(compact)
        identity=event.id
        records=1
        old_size=0
        args=(key,receiver,function,end,start)
        for row in store.execute('SELECT k,id,receiver,function,start,end,records,first,last '
                'FROM ics_discovery WHERE k=? AND receiver=? AND function=? AND start<=? AND end>=?',args):
            old_size+=self._discovery_size(row)
            records+=row[6]
            if (row[4],row[1])<(start,identity):
                start,identity,first=row[4],row[1],row[7]
            if (expand_event(row[8]).ts,expand_event(row[8]).id)>(expand_event(last).ts,expand_event(last).id):
                last=row[8]
            end=max(end,row[5])
        row=(key,identity,receiver,function,start,end,records,first,last)
        delta=self._discovery_size(row)-old_size
        if delta>0 and not self.room():
            self.owner.refuse('ics_discovery_history','The disk budget refused coalesced ICS discovery history.')
            return
        store.cap()
        try:
            store.db.execute('SAVEPOINT ics_discovery_merge')
            store.db.execute('DELETE FROM ics_discovery WHERE k=? AND receiver=? AND function=? AND start<=? AND end>=?',args)
            store.db.execute('INSERT INTO ics_discovery VALUES(?,?,?,?,?,?,?,?,?)',row)
            store.db.execute('RELEASE ics_discovery_merge')
        except sqlite3.OperationalError as error:
            store.db.rollback()
            raise store.failed(error,account=self.account) from error
        finally:
            store.grew()
        self.owner.state_budget().charge(self.account,delta)

    def exception_identity(self,event):
        store=self.store()
        stamp=event.ts.timestamp()
        key=row_key(event.get('zeek.uid'),event.get('ics.transaction_id'),event.get('ics.protocol'),
                    event.get('ics.function_code'),event.get('ics.function_name'),event.get('ics.unit'),
                    event.get('ics.address'),event.get('ics.quantity'),event.get('ics.status'),
                    event.get('ics.status_code'),event.get('ics.error_class'),event.get('ics.iin'),*_peers(event))
        sensor=event.get('observer.name') or event.host
        cutoff=stamp-SENSOR_COPY_SECONDS
        expired=store.execute('SELECT COALESCE(SUM(LENGTH(k)+LENGTH(id)+96),0) FROM ics_copies WHERE ts<?',
                              (cutoff,)).fetchone()[0]
        expired+=store.execute('SELECT COALESCE(SUM(LENGTH(s.k)+LENGTH(s.id)+LENGTH(CAST(s.sensor AS BLOB))+96),0) '
            'FROM ics_copy_sensors s JOIN ics_copies c ON c.k=s.k AND c.id=s.id WHERE c.ts<?',
            (cutoff,)).fetchone()[0]
        row=store.execute('SELECT c.id FROM ics_copies c WHERE c.k=? AND c.ts>=? AND c.ts<=? '
            'AND NOT EXISTS(SELECT 1 FROM ics_copy_sensors s WHERE s.k=c.k AND s.id=c.id AND s.sensor=?) '
            'ORDER BY c.ts DESC,c.id LIMIT 1',(key,cutoff,stamp,sensor)).fetchone()
        identity=row[0] if row else event.id
        size=len(key.encode())+len(identity.encode())+len(sensor.encode())+96
        if row is None:
            size+=len(key.encode())+len(identity.encode())+96
        if size>expired and not self.room():
            self.owner.refuse('ics_copy_identity','The disk budget refused ICS cross-sensor exception identity.')
            return None
        store.cap()
        try:
            store.db.execute('SAVEPOINT ics_copy')
            store.db.execute('DELETE FROM ics_copy_sensors WHERE EXISTS(SELECT 1 FROM ics_copies c '
                'WHERE c.k=ics_copy_sensors.k AND c.id=ics_copy_sensors.id AND c.ts<?)',(cutoff,))
            store.db.execute('DELETE FROM ics_copies WHERE ts<?',(cutoff,))
            if row is None:
                store.db.execute('INSERT INTO ics_copies VALUES(?,?,?)',(key,identity,stamp))
            store.db.execute('INSERT INTO ics_copy_sensors VALUES(?,?,?)',(key,identity,sensor))
            store.db.execute('RELEASE ics_copy')
        except sqlite3.OperationalError as error:
            store.db.rollback()
            raise store.failed(error,account=self.account) from error
        finally:
            store.grew()
        self.owner.state_budget().charge(self.account,size-expired)
        return identity

    def reset_copies(self):
        store=self.store()
        size=store.execute('SELECT COALESCE(SUM(LENGTH(k)+LENGTH(id)+96),0) FROM ics_copies').fetchone()[0]
        size+=store.execute('SELECT COALESCE(SUM(LENGTH(k)+LENGTH(id)+LENGTH(CAST(sensor AS BLOB))+96),0) '
                           'FROM ics_copy_sensors').fetchone()[0]
        store.write('DELETE FROM ics_copy_sensors',[()])
        store.write('DELETE FROM ics_copies',[()])
        self.owner.state_budget().charge(self.account,-size)


def _peers(event):
    sender, receiver = event.get('ics.sender'), event.get('ics.receiver')
    if not isinstance(sender,str) or not isinstance(receiver,str):
        return None
    return (sender,receiver) if sender and receiver and sender!=receiver else None


def _declared(owner, sender):
    facts = getattr(owner,'site_facts',None)
    hosts = getattr(facts,'ics_control_hosts',())
    declared = bool(hosts) or 'ics_control_hosts' in (getattr(facts,'content',None) or {})
    return declared, address_member(sender,hosts)


def _request_peers(event):
    if event.get('ics.is_request') is True:
        return _peers(event)
    if (event.get('ics.is_request') is None and event.get('ics.protocol') in {'dnp3','modbus'}
            and event.get('ics.request_observed') is True):
        sender,receiver=event.get('conn.orig_h'),event.get('conn.resp_h')
        if isinstance(sender,str) and isinstance(receiver,str) and sender and receiver and sender!=receiver:
            return sender,receiver
    return None


def _pair(event):
    if not event.has('zeek.uid') or not event.has('ics.transaction_id') or not (peers:=_peers(event)):
        return None
    if event.get('ics.is_request') is False:
        peers = tuple(reversed(peers))
    elif event.get('ics.is_request') is not True:
        return None
    return row_key(event.get('observer.name') or event.host,event.get('zeek.uid'),
                   event.get('ics.transaction_id'),event.get('ics.protocol'),
                   event.get('ics.function_code'),event.get('ics.unit'),*peers)


class _Command(ZeekBehaviorRule):
    attack_domain = 'ics'
    families = ('ics_tx',)
    required_fields = ('ics.protocol','ics.op_class')
    uses_site_facts = True
    research = (_DOC,)
    positive_only_reason = ('ICS requests and matching response observations establish network messages only; '
                            'they do not establish a physical process outcome.')
    benign = ('Authorized operations and maintenance can produce these commands.',)
    operations = frozenset()

    def selected_operation(self,event):
        return event.get('ics.op_class') in self.operations

    def _unjudged(self,key,text):
        counts=self.__dict__.setdefault('_ics_unjudged',{})
        counts[key]=counts.get(key,0)+1
        self.missing_required+=1
        self._cov_notes[key]=text.format(count=counts[key])

    def __init__(self):
        super().__init__()
        self.rows = _IcsRows(self)

    @staticmethod
    def raw_weight(event):
        return 1

    def _note_group(self, shape, hit, event, *, new_host, link_host=True):
        group = super()._note_group(shape,hit,event,new_host=new_host,link_host=link_host)
        if group is not None and not hasattr(group,'acks'):
            group.acks,group.responses = 0,[]
        return group

    def record_match(self,event,hit):
        match=super().record_match(event,hit)
        match.claim=f'{hit.text}; 1 request record(s), first {event.ts.isoformat()}, last {event.ts.isoformat()}.'
        match.attack=hit.attack
        return match

    def _network_claim(self, match, group):
        first = datetime.fromtimestamp(group.ends.first[0],UTC).isoformat() if group.ends.first else '?'
        last = datetime.fromtimestamp(group.ends.last[0],UTC).isoformat() if group.ends.last else '?'
        match.claim = f'{group.common}; {group.records} request record(s), first {first}, last {last}.'
        if getattr(group,'acks',0):
            verb = 'write' if self.id=='ics.write_or_control_command' else 'command'
            match.claim += f' {group.acks} {verb} acknowledged without exception by a paired response.'
        match.notes = [*getattr(group,'zeek_notes',()),'Network messages do not establish a physical process outcome.',
                       'ATT&CK for ICS context (not proof): '+', '.join(group.attack)]
        responses=[expand_event(value) for value in getattr(group,'responses',())]
        ids={event.id for event in match.events}
        match.events.extend(event for event in responses if event.id not in ids)
        match.context_ids.update(event.id for event in responses)
        match.predicate.extend(pf(event,name) for event in responses
            for name in ('ics.is_request','ics.exception','ics.transaction_id') if event.has(name))
        match.fleet_hosts,match.fleet_host_count,match.fleet_hosts_complete=(),0,False
        match.bounded_revision=True
        match.revision_reason='ICS request tally and bounded first/last response witnesses replace the earlier summary.'
        match.attack=tuple(group.attack)
        return match

    def _ack(self, request, response):
        if response.get('ics.exception') is not False or request.ts>response.ts:
            return []
        if (response.ts-request.ts).total_seconds()>PAIR_SECONDS:
            return []
        marker='ack-request:'+request.id
        response_marker='ack-response:'+response.id
        if self.rows.marked(marker) or self.rows.marked(response_marker):
            return []
        hits=self.judge(request)
        if not hits:
            return []
        shape=self._shape(request,hits[0])
        group=self.groups.get(shape)
        if group is None:
            return []
        self.rows.remember(marker,'1')
        self.rows.remember(response_marker,'1')
        if not self.rows.marked(marker) or not self.rows.marked(response_marker):
            self.note_coverage('ics_ack_pairing','ICS response-pair identity could not be retained; acknowledgement counts are partial.')
            return []
        group.acks=getattr(group,'acks',0)+1
        payload=compact_event(response.model_copy(update={'fields':{
            name:fact for name,fact in response.fields.items() if name in _FIELDS}}))
        held=[*getattr(group,'responses',()),payload]
        held.sort(key=lambda value:(expand_event(value).ts,expand_event(value).id))
        group.responses=held if len(held)<=2 else [held[0],held[-1]]
        self.groups.put(shape,group)
        self.rows.remember('ack-group:'+shape,'1')
        return []

    def consume(self, events):
        out=[]
        for event in sorted(events,key=lambda item:(item.ts,item.id)):
            if event.family!='ics_tx':
                continue
            is_request=event.get('ics.is_request')
            summary_request = (is_request is None and event.get('ics.request_observed') is True
                               and event.get('ics.protocol') in {'modbus','dnp3'})
            if is_request is not True and is_request is not False and not summary_request:
                self.missing_required+=1
                self.note_coverage('ics_direction','ICS request/response direction is unknown; command direction was not evaluated.')
                continue
            pair=_pair(event)
            if is_request is True or summary_request:
                if event.get('ics.op_class')=='other' and event.get('ics.protocol') in WRITE_PROTOCOLS:
                    self._unjudged('ics_unknown_function',
                        '{count} requests used functions outside the catalogue and were not judged.')
                    continue
                if not _request_peers(event):
                    self._unjudged('ics_request_endpoints','{count} ICS requests had no typed endpoints.')
                    continue
                out.extend(super().consume([event]))
                if pair and self.judge(event):
                    self.rows.put('request:'+pair,event)
            elif pair and self.selected_operation(event):
                if self.rows.put('response:'+pair,event):
                    self._pending.append(event)
        return out

    def finalize(self):
        # Only the complete retained exchange set can resolve a reused transaction identifier independently
        # of source/partition arrival order. Each response and request participates at most once. Immediate
        # request findings remain valid while this optional acknowledgement refinement waits for finalize.
        if self.rows.ready:
            store=self.rows.store()
            for key,response,_raw,_value in self.rows.iterate(prefix='response:'):
                pair=key.removeprefix('response:')
                row=store.execute('SELECT r.event,r.raw FROM windows_rows r WHERE r.k=? AND r.ts>=? AND r.ts<=? '
                    "AND NOT EXISTS(SELECT 1 FROM windows_marks m WHERE m.k='ack-request:'||r.id) "
                    'ORDER BY r.ts DESC,r.id LIMIT 1',('request:'+pair,
                        response.ts.timestamp()-PAIR_SECONDS,response.ts.timestamp())).fetchone()
                if row:
                    self._ack(self.rows.hydrate(row)[0],response)
        yield from super().finalize()
        if self.rows.ready:
            for (marker,) in self.rows.store().execute("SELECT k FROM windows_marks WHERE k LIKE 'ack-group:%' ORDER BY k"):
                shape=marker.removeprefix('ack-group:')
                group=self.groups.peek(shape)
                if group is not None and group.repeats<=0 and not group.emitted_records:
                    match=self._fleet_match(shape,group,final=True)
                    if match is not None:
                        yield match

    def _hit(self,event,lane,*,notes=()):
        sender,receiver=_request_peers(event)
        protocol=event.get('ics.protocol')
        function=event.get('ics.function_name') or event.get('ics.function_code')
        kind='write' if self.id=='ics.write_or_control_command' else 'command'
        text=f'{kind} request observed from {sender} to {receiver} over {protocol}: {function}'
        if event.get('ics.is_request') is None:
            label={'dnp3':'DNP3','modbus':'Modbus'}[protocol]
            notes=(*notes,(f'The {label} transaction summary explicitly records a request. Endpoints are its '
                   'connection client/server roles; packet direction and acknowledgement are unknown.'))
        notes=tuple(dict.fromkeys([*notes,*event.caveats]))
        return signal(event,self.id,text,self.attack,tuple(sorted(_FIELDS)),lane=lane,
            severity='high' if lane=='high' else 'info' if lane=='context' else 'medium',notes=notes,
            content=row_key(sender,receiver,protocol,function),common=text)

    def release_state(self):
        self.rows.close()
        super().release_state()


class WriteOrControlCommand(_Command):
    id='ics.write_or_control_command'
    version = "2"
    title='ICS write or control request observed'
    attack=('T1692.001','T0836','T0831')
    operations=frozenset({'write','control'})

    def judge(self,event):
        if not self.selected_operation(event) or not (peers:=_request_peers(event)):
            return []
        declared,allowed=_declared(self,peers[0])
        lane='context' if allowed else 'high' if declared else 'lead'
        notes=() if declared else ('ICS control hosts are not declared',)
        return [self._hit(event,lane,notes=notes)]


class ModeChangeOrRestart(_Command):
    id='ics.mode_change_or_restart'
    version = "2"
    title='ICS mode-change or restart request observed'
    attack=('T0858','T0816')
    operations=frozenset({'mode_change','restart'})

    def judge(self,event):
        if not self.selected_operation(event) or not (peers:=_request_peers(event)):
            return []
        _,allowed=_declared(self,peers[0])
        return [self._hit(event,'lead' if allowed else 'high')]


class ProgramTransfer(_Command):
    id='ics.program_transfer'
    version = "2"
    title='ICS program upload or download request observed'
    attack=('T0843','T0845')
    operations=frozenset({'program_transfer'})

    def judge(self,event):
        if not self.selected_operation(event) or not (peers:=_request_peers(event)):
            return []
        direction=event.get('ics.program_direction')
        if direction not in {'upload','download'}:
            self.note_coverage('ics_program_direction','ICS program-transfer direction was not typed; upload/download lane unresolved.')
            return []
        _,allowed=_declared(self,peers[0])
        hit=self._hit(event,'lead' if direction=='upload' or allowed else 'high')
        hit.attack=('T0845',) if direction=='upload' else ('T0843',)
        return [hit]


class _Population(Playbook):
    attack_domain='ics'
    families=('ics_tx',)
    required_fields=('ics.protocol',)
    kind='aggregate'
    claim_type='network_observation'
    assures_negative=False
    positive_only_reason='ICS network observations establish positive messages only.'
    uses_site_facts=True
    benign=('A misconfigured poller or authorized engineering tool can produce these observations.',)
    next_checks=('Review passive packet evidence and the device owner\'s maintenance records.',)

    def __init__(self):
        super().__init__()
        self.rows=_IcsRows(self)

    def retained_events(self):
        return []

    def consume(self,events):
        for event in self.applicable(events):
            if not self.selected(event):
                continue
            peers=_request_peers(event) if self.id=='ics.remote_discovery' else _peers(event)
            if not peers:
                self.evaluated-=1
                self.missing_required+=1
                self._missing_endpoints=getattr(self,'_missing_endpoints',0)+1
                kind='requests' if self.id=='ics.remote_discovery' else 'exception responses'
                self._cov_notes['ics_endpoints']=f'{self._missing_endpoints} ICS {kind} had no typed endpoints.'
                continue
            sender,receiver=peers
            key=row_key(sender,event.get('ics.protocol'))
            if self.id=='ics.remote_discovery':
                self.rows.discovery_put(key,event,peers)
                continue
            self.rows.put(key,event,receiver if self.id=='ics.remote_discovery' else event.id)
        return []

    def _match(self,key,first,last,count,examples,lane):
        events=list({event.id:event for event in examples}.values())
        peer,protocol=json.loads(key)
        if self.id=='ics.remote_discovery':
            claim=f'ICS discovery requests from {peer} over {protocol} reached {count} distinct receivers within ten minutes'
        else:
            claim=f'{count} exception responses from {peer} over {protocol} to distinct recorded requests within ten minutes'
        claim+=f'; first {first.isoformat()}, last {last.isoformat()}.'
        return Match(self.id,claim,self.claim_type,events,
            [pf(event,name) for event in events for name in sorted(_FIELDS) if event.has(name)],
            first,'medium' if lane=='lead' else 'info',lane,'medium',
            [entity for event in events for entity in event.entities()],
            list(self.benign)+['Network messages do not establish a physical process outcome.'],
            group_key=self.id+'|'+key,attack=self.attack)

    def finalize(self):
        if not self.rows.ready:
            return
        store=self.rows.store()
        key=None
        count=peak=0
        first=last=None
        examples=[]
        context=[]
        for current,event,_raw,value in self.rows.iterate():
            if current!=key:
                if key is not None:
                    result=self._finish_group(key,peak,first,last,examples,context)
                    if result:
                        yield result
                store.write('DELETE FROM ics_active',[()])
                if self.id=='ics.exception_burst':
                    self.rows.reset_copies()
                key=current
                count=peak=0
                first=last=None
                examples=[]
                context=[]
            stamp=event.ts.timestamp()
            if self.id=='ics.exception_burst':
                value=self.rows.exception_identity(event)
                if value is None:
                    continue
            cutoff=stamp-WINDOW_SECONDS
            expired=store.execute('SELECT COUNT(*) FROM ics_active WHERE ts<?',(cutoff,)).fetchone()[0]
            store.write('DELETE FROM ics_active WHERE ts<?',[(cutoff,)])
            count-=expired
            existing=store.execute('SELECT 1 FROM ics_active WHERE value=?',(value,)).fetchone()
            if not existing:
                count+=1
            store.write('INSERT OR REPLACE INTO ics_active VALUES(?,?)',[(value,stamp)])
            if len(context)<2:
                context.append(event)
            if count>peak:
                peak=count
                first=datetime.fromtimestamp(max(cutoff,store.execute(
                    'SELECT MIN(ts) FROM ics_active').fetchone()[0]),UTC)
                last=event.ts
                # Each qualifying window keeps its first and last witnesses plus at most threshold distinct
                # members. Larger counts remain exact; the citation list is bounded independently.
                rows=self.rows.witnesses(key,stamp,WINDOW_SECONDS,self.threshold,distinct=True)
                examples=[row[0] for row in rows]
                if event.id not in {item.id for item in examples}:
                    examples.append(event)
        if key is not None:
            result=self._finish_group(key,peak,first,last,examples,context)
            if result:
                yield result

    def _finish_group(self,key,peak,first,last,examples,context):
        if peak>=self.threshold:
            return self._match(key,first,last,peak,examples,'lead')
        if (self.id=='ics.remote_discovery' and context and (peers:=_request_peers(context[0]))
                and _declared(self,peers[0])[1]):
            return self._match(key,context[0].ts,context[-1].ts,peak,context,'context')
        return None

    def release_state(self):
        self.rows.close()


class RemoteDiscovery(_Population):
    id='ics.remote_discovery'
    version = "2"
    title='ICS discovery fan-out observed'
    attack=('T0888','T0846')
    threshold=DISCOVERY_RECEIVERS

    @staticmethod
    def selected(event):
        return (event.get('ics.op_class')=='discovery'
                and (event.get('ics.is_request') is True or event.get('ics.request_observed') is True))

    def finalize(self):
        if not self.rows.ready:
            return
        store=self.rows.store()
        key=None
        count=peak=0
        first=last=earliest=None
        examples=[]
        context=[]
        query=('SELECT k,start AS stamp,1 AS delta,id,receiver,first FROM ics_discovery UNION ALL '
               'SELECT k,end AS stamp,-1 AS delta,id,receiver,first FROM ics_discovery '
               'ORDER BY k,stamp,delta DESC,id')
        for current,stamp,delta,_identity,receiver,payload in store.execute(query):
            if current!=key:
                if key is not None:
                    result=self._finish_group(key,peak,first,last,examples,context)
                    if result:
                        yield result
                released=store.execute('SELECT COALESCE(SUM(LENGTH(receiver)+104),0) FROM ics_discovery_active').fetchone()[0]
                store.write('DELETE FROM ics_discovery_active',[()])
                self.state_budget().charge(self.rows.account,-released)
                key=current
                count=peak=0
                first=last=None
                earliest=stamp
                examples=[]
                context=[expand_event(payload)]
            prior=store.execute('SELECT copies FROM ics_discovery_active WHERE receiver=?',(receiver,)).fetchone()
            copies=(prior[0] if prior else 0)+delta
            if copies>0:
                store.write('INSERT OR REPLACE INTO ics_discovery_active VALUES(?,?)',[(receiver,copies)])
                if not prior:
                    count+=1
                    self.state_budget().charge(self.rows.account,len(receiver.encode())+104)
            elif prior:
                store.write('DELETE FROM ics_discovery_active WHERE receiver=?',[(receiver,)])
                count-=1
                self.state_budget().charge(self.rows.account,-len(receiver.encode())-104)
            if delta>0 and count>peak:
                peak=count
                first=datetime.fromtimestamp(max(earliest,stamp-WINDOW_SECONDS),UTC)
                last=datetime.fromtimestamp(stamp,UTC)
                examples=[]
                witness=('SELECT d.first,d.last FROM ics_discovery d WHERE d.k=? AND d.start<=? AND d.end>=? '
                    'AND NOT EXISTS(SELECT 1 FROM ics_discovery p WHERE p.k=d.k AND p.receiver=d.receiver '
                    'AND p.start<=? AND p.end>=? AND (p.start>d.start OR (p.start=d.start AND p.id<d.id))) '
                    'ORDER BY d.receiver LIMIT ?')
                for left,right in store.execute(witness,(key,stamp,stamp,stamp,stamp,self.threshold)):
                    examples.extend([expand_event(left),expand_event(right)])
        if key is not None:
            result=self._finish_group(key,peak,first,last,examples,context)
            if result:
                yield result

    def _match(self,key,first,last,count,examples,lane):
        match=super()._match(key,first,last,count,examples,lane)
        match.claim=match.claim.replace('; first ', '; qualifying window start ').replace(', last ', ', end ')
        match.ts=min(event.ts for event in match.events)
        match.notes.append('Distinct-device counts use exact coalesced discovery windows. Bounded citations show '
            'first/last requests of retained intervals and may lie outside the peak window.')
        if any(event.get('ics.is_request') is None and event.get('ics.request_observed') is True
               for event in match.events):
            match.notes.append('Discovery summaries use logical connection client/server roles; packet direction '
                               'and acknowledgement are unknown.')
        match.notes.extend(dict.fromkeys(note for event in match.events for note in event.caveats))
        return match


class ExceptionBurst(_Population):
    id='ics.exception_burst'
    version = "2"
    title='ICS exception response burst observed'
    attack=('T0814',)
    threshold=EXCEPTION_REQUESTS

    def selected(self,event):
        if event.get('ics.exception') is not True or event.get('ics.is_request') is not False:
            return False
        observer=event.get('observer.name') or event.host
        if not isinstance(observer,str) or not observer:
            self.evaluated-=1
            self.missing_required+=1
            self._missing_observer=getattr(self,'_missing_observer',0)+1
            self._cov_notes['ics_exception_observer']=(f'{self._missing_observer} ICS exception records had no '
                'observer identity; cross-sensor copies could not be resolved and these rows were not judged.')
            return False
        if event.get('zeek.uid') in (None,'') or event.get('ics.transaction_id') in (None,''):
            self.evaluated-=1
            self.missing_required+=1
            self.note_coverage('ics_exception_identity','ICS exception rows without connection and transaction '
                               'identity cannot establish distinct failed requests; burst counts were not evaluated.')
            return False
        return True


RULES=(WriteOrControlCommand,ModeChangeOrRestart,ProgramTransfer,RemoteDiscovery,ExceptionBurst)
