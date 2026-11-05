"""Bounded connection canonicalization before rules consume cumulative counters."""
from datetime import datetime, timedelta
from itertools import batched

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek_catalog import CONN
from romulus.hunt.zeek_sources import key_intents
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Window


def connection(event):
    return event.get('observer.product')=='zeek' and event.get('zeek.log')=='conn' and event.has('zeek.uid')


def overlaps(event,window):
    start=datetime.fromisoformat(event.get('flow.start')) if event.has('flow.start') else event.ts
    end=datetime.fromisoformat(event.get('flow.end')) if event.has('flow.end') else start
    return start < window.end and (end > window.start or start==end and start>=window.start)


# Selection notes for net_flow cells: the records were read, so neither makes a sensor's inventory incomplete.
INTERIM_SELECTED=('latest interim connection selected by greatest cumulative duration; source start time does not '
                  'establish write order')
UNKNOWN_END=' connections before the window had no recorded end'


def selection_note(reason):
    return reason==INTERIM_SELECTED or reason.endswith(UNKNOWN_END)


def canonical(sweep,events,raw,reasons):
    """Select final or latest cumulative record once per sensor/UID, across all targets.

    Lookups cover only interim keys already fetched, in batches of at most 1,000.
    A disk tombstone prevents both cumulative versions entering rule state.
    Lookup incompleteness is named; strong positives still consume immediately.
    """
    stage=sweep._event_stage()
    if reason := getattr(sweep,'_zeek_canonical_unavailable',''):
        reasons.append((reason,frozenset({'net_flow'})))
        return [event for event in events if not connection(event) or overlaps(event,sweep.window)]
    def refused():
        reason=('Zeek canonical-flow disk state incomplete: '+stage.refusal_reason+
                '; cumulative flow counts withheld; direct record positives remain eligible')
        sweep._zeek_canonical_unavailable=reason
        reasons.append((reason,frozenset({'net_flow'})))
    if not getattr(stage,'_zeek_canonical_table',False):
        before=stage.refused
        def create():
            stage.db.execute('CREATE TABLE IF NOT EXISTS zeek_canonical(sensor TEXT,uid TEXT,event_id TEXT, '
                             'PRIMARY KEY(sensor,uid)) WITHOUT ROWID')
            stage.db.commit()
        stage._write(create,1,estimated_bytes=4096)
        if stage.refused>before:
            refused()
            return [event for event in events if not connection(event) or overlaps(event,sweep.window)]
        stage._zeek_canonical_table=True
    chosen={}
    others=[]
    unknown_ends = 0
    for event in events:
        if not connection(event):
            others.append(event);continue
        if not overlaps(event,sweep.window):
            if event.get('conn.interim') is True and not event.has('flow.end') and event.ts<sweep.window.start:
                unknown_ends += 1
            continue
        key=(event.host or '',str(event.get('zeek.uid')))
        prior_id=stage.db.execute('SELECT event_id FROM zeek_canonical WHERE sensor=? AND uid=?',key).fetchone()
        if prior_id:
            if prior_id[0]==event.id:
                sweep.repo.merge_evidence_raw(sweep.hunt_id,[event],raw)
            continue
        prior=chosen.get(key)
        if prior is None or rank(event)>rank(prior):
            chosen[key]=event
    if unknown_ends:
        reasons.append((f'{unknown_ends}{UNKNOWN_END}',frozenset({'net_flow'})))
    pending=[key for key,event in chosen.items() if event.get('conn.interim') is True]
    for keys in batched(pending,1000):
        scoped=Window(start=min(chosen[key].ts for key in keys)-timedelta(seconds=1),
                      end=sweep.window.end+timedelta(minutes=5))
        intents={}
        for sensor in sorted({key[0] for key in keys}):
            uids=[uid for who,uid in keys if who==sensor]
            plan=key_intents(sweep.contracts,[CONN],sensor,{'zeek.uid'},uids,scoped,limit=10000)
            reasons.extend((reason,frozenset({'net_flow'})) for reason in plan.reasons)
            for intent in plan.intents:
                if intent.target in intents:
                    intents[intent.target].any_of.extend(intent.any_of)
                else:
                    intents[intent.target]=intent
        remaining=10000
        queries=0
        def spend():
            nonlocal queries
            if queries>=128:
                return False
            queries+=1
            sweep.heartbeat()
            return True
        if not intents:
            reasons.append(('Zeek cumulative-flow source key/sensor is not searchable; latest record unresolved',
                            frozenset({'net_flow'})))
        for target,intent in intents.items():
            if remaining<=0:
                reasons.append(('Zeek cumulative-flow lookup shared row limit 10000 reached; latest record unresolved',
                                frozenset({'net_flow'})));break
            cap=remaining if remaining<=2000 else remaining//2000*2000
            intent=intent.model_copy(update={'max_records':cap,'purpose':'sweep:zeek-canonical'})
            out=execute(sweep.client,intent,sweep.contracts[target],on_query=spend)
            remaining-=out.returned
            if out.completeness!=Completeness.complete:
                reasons.append(('Zeek cumulative-flow lookup incomplete: '+'; '.join(out.reasons),frozenset({'net_flow'})))
            found,_,errors=normalize_hits(out.records,contract=sweep.contracts[target],surrogate_free=getattr(out,"surrogate_free",False))
            copies={f"{hit['_index']}/{hit['_id']}":hit['_source'] for hit in out.records}
            if errors:
                reasons.append(('Zeek cumulative-flow lookup normalization incomplete',frozenset({'net_flow'})))
            for event in found:
                key=(event.host or '',str(event.get('zeek.uid')))
                if connection(event) and key in chosen and rank(event)>rank(chosen[key]):
                    chosen[key]=event
                elif key in chosen and event.id==chosen[key].id:
                    refs={ref.key:ref for ref in [*chosen[key].raw,*event.raw]}
                    chosen[key]=chosen[key].model_copy(update={'raw':list(refs.values())})
            raw.update({ref.key:copies[ref.key] for key in keys for ref in chosen[key].raw if ref.key in copies})
        if any(chosen[key].get('conn.interim') is True for key in keys):
            reasons.append((INTERIM_SELECTED,frozenset({'net_flow'})))
    if chosen:
        before=stage.refused
        def remember():
            stage.db.executemany('INSERT OR IGNORE INTO zeek_canonical VALUES (?,?,?)',
                                 ((*key,event.id) for key,event in chosen.items()))
            stage.db.commit()
        stage._write(remember,len(chosen),estimated_bytes=sum(
            len(sensor.encode('utf-8'))+len(uid.encode('utf-8'))+len(event.id)+64
            for (sensor,uid),event in chosen.items()))
        if stage.refused>before:
            refused()
    others.extend(chosen.values())
    return others


def rank(event):
    return (event.get('conn.interim') is not True,event.get('session.duration_s') or 0,event.id)
