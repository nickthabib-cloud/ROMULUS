"""Bounded source-backed Sweep lookups for cross-record content gaps."""
from datetime import timedelta

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek_catalog import ZEEK_LOGS
from romulus.hunt.zeek_context import (
    FILE_FIELDS,
    MAX_KEYS,
    MAX_ROWS,
    UID_FIELDS,
    _keys,
    _note,
    attach,
    related,
)
from romulus.hunt.zeek_sources import key_intents
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, Window

MAX_QUERIES = 128


def enrich(sweep,match,raw):
    anchors=[event for event in match.events if event.get('observer.product')=='zeek']
    if not anchors:
        return
    latest=max(event.ts for event in anchors)
    if window := getattr(sweep,'window',None):
        latest=max(latest,window.end)
    scope=Window(start=min(event.ts for event in anchors)-timedelta(hours=sweep.site_facts.zeek.connection_lookback_hours),
                 end=latest+timedelta(minutes=5))
    fetched={event.id:event for event in anchors}
    queried=set();remaining=MAX_ROWS;queries=0
    def spend():
        nonlocal queries
        if queries>=MAX_QUERIES:
            return False
        queries+=1
        if heartbeat := getattr(sweep,'heartbeat',None):
            heartbeat()
        return True
    for _ in range(2):
        connected=related(match,list(fetched.values()))
        intents={}
        for sensor,scoped_keys in sorted(_keys(match,connected).items()):
            for kind,fields,logs in (('uid',UID_FIELDS,{'conn','files'}),('fuid',FILE_FIELDS,{'files'})):
                keys={key for key_kind,key in scoped_keys if key_kind==kind and (sensor,kind,key) not in queried}
                if len(queried)+len(keys)>MAX_KEYS:
                    _note(match,'content-gap join key limit 1000 reached; remaining witnesses unresolved')
                    keys=set(sorted(keys)[:max(0,MAX_KEYS-len(queried))])
                queried.update((sensor,kind,key) for key in keys)
                plan=key_intents(sweep.contracts,[log for log in ZEEK_LOGS if log.name in logs],sensor,set(fields),keys,scope)
                for reason in plan.reasons:
                    _note(match,reason)
                for intent in plan.intents:
                    if intent.target in intents:
                        intents[intent.target].any_of.extend(intent.any_of)
                    else:
                        intents[intent.target]=intent
        for target,intent in intents.items():
            if remaining<=0 or queries>=MAX_QUERIES:
                _note(match,'content-gap witness shared row/query bound reached; remaining joins unresolved');break
            cap=remaining if remaining<=2000 else remaining//2000*2000
            out=execute(sweep.client,intent.model_copy(update={'max_records':cap,'purpose':'sweep:zeek-content-gaps'}),
                        sweep.contracts[target],on_query=spend)
            remaining-=out.returned
            if out.completeness!=Completeness.complete:
                _note(match,'content-gap witness retrieval incomplete: '+'; '.join(out.reasons))
            events,_,errors=normalize_hits(out.records,contract=sweep.contracts[target],surrogate_free=getattr(out,"surrogate_free",False))
            if errors:
                _note(match,'content-gap witness normalization incomplete')
            fetched.update((event.id,event) for event in events)
            raw.update({f"{hit['_index']}/{hit['_id']}":hit['_source'] for hit in out.records})
    attach(match,list(fetched.values()))
