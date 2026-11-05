"""Query-aware synthetic Elasticsearch for native Zeek fixtures; no external telemetry."""
import copy
import fnmatch
import itertools
from datetime import UTC, datetime

from tests.throughput_fixture import MiniES


def value(source, path):
    # Elasticsearch's default dynamic keyword multi-field is indexed beside
    # text, and never appears as a separate key in _source.
    if path.endswith('.keyword'):
        path = path.removesuffix('.keyword')
    if path in source:
        return source[path]
    current = source
    for part in path.split('.'):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def number(item, field=None):
    if isinstance(item, str):
        try:
            return datetime.fromisoformat(item).timestamp()
        except ValueError:
            return float(item)
    return item/1000 if isinstance(item,(float,int)) and field in ('firstPacket','lastPacket') else item


def matches(query, source):
    if not query or 'match_all' in query:
        return True
    kind, spec = next(iter(query.items()))
    if kind == 'bool':
        def entries(name):
            vals = spec.get(name, [])
            return vals if isinstance(vals, list) else [vals]
        if not all(matches(item, source) for item in entries('must')+entries('filter')):
            return False
        if any(matches(item, source) for item in entries('must_not')):
            return False
        return sum(matches(item, source) for item in entries('should')) >= spec.get(
            'minimum_should_match', 1 if entries('should') else 0)
    if kind == 'exists':
        return value(source, spec['field']) is not None
    field, expected = next(iter(spec.items()))
    actual = value(source, field)
    actuals = actual if isinstance(actual, list) else [actual]
    if kind in ('term','terms'):
        expected = expected if kind == 'terms' else [expected]
        return any(item in expected for item in actuals)
    if kind == 'wildcard':
        return any(isinstance(item,str) and fnmatch.fnmatchcase(item.casefold(), expected['value'].casefold()) for item in actuals)
    if kind == 'range':
        if actual is None:
            return False
        actual = number(actual,field)
        return all({'gte': actual >= number(bound,field), 'gt': actual > number(bound,field),
                    'lte': actual <= number(bound,field), 'lt': actual < number(bound,field)}[op]
                   for op,bound in expected.items() if op != 'format')
    raise AssertionError(f'unsupported synthetic query: {kind}')


class ZeekES(MiniES):
    def __init__(self, docs, time_fields):
        self.docs = docs
        self.time_fields = time_fields
        self.pits = {}
        self.requests = 0
        self.queries = []

    def _search(self, target, body):
        self.queries.append((target,copy.deepcopy(body)))
        docs = [doc for doc in self.docs[target] if matches(body.get('query', {}), doc['_source'])]
        out = {'timed_out':False, '_shards':{'failed':0}, 'hits':{'total':{'value':len(docs),'relation':'eq'},'hits':[]}}
        if body.get('aggs'):
            out['aggregations'] = {name:self.aggregate(spec,docs) for name,spec in body['aggs'].items()}
        if body.get('size',10):
            field = next(iter(body.get('sort',[{self.time_fields[target]:{}}])[0]))
            rows = sorted(enumerate(docs),key=lambda pair:(number(value(pair[1]['_source'],field),field),pair[0]))
            desc = body.get('sort',[{field:{'order':'asc'}}])[0][field].get('order') == 'desc'
            if desc:
                rows.reverse()
            after=body.get('search_after')
            if after:
                mark=(number(after[0],field),after[1])
                rows=[pair for pair in rows if ((number(value(pair[1]['_source'],field),field),pair[0]) < mark if desc
                     else (number(value(pair[1]['_source'],field),field),pair[0]) > mark)]
            for i,doc in rows[:body.get('size',10)]:
                stamp=value(doc['_source'],field)
                out['hits']['hits'].append({**doc,'sort':[stamp,i]})
            if 'pit' in body:
                out['pit_id']=body['pit']['id']
        return out

    def aggregate(self, spec, docs):
        if 'filter' in spec:
            chosen=[doc for doc in docs if matches(spec['filter'],doc['_source'])]
            return {'doc_count':len(chosen), **{name:self.aggregate(sub,chosen) for name,sub in spec.get('aggs',{}).items()}}
        for mode in ('min','max','sum','value_count'):
            if mode in spec:
                vals=[number(value(doc['_source'],spec[mode]['field'])) for doc in docs
                      if value(doc['_source'],spec[mode]['field']) is not None]
                result=(len(vals) if mode=='value_count' else sum(vals) if mode=='sum' else
                        min(vals) if mode=='min' and vals else max(vals) if vals else None)
                return {'value':result}
        if 'composite' in spec:
            comp=spec['composite']; groups={}; names=[next(iter(item)) for item in comp['sources']]
            for doc in docs:
                choices=[]
                for item in comp['sources']:
                    cfg=next(iter(item.values())); kind,definition=next(iter(cfg.items()))
                    raw=value(doc['_source'],definition['field'])
                    if kind=='date_histogram':
                        step=int(definition['fixed_interval'].rstrip('s')); raw=int(number(raw,definition['field'])//step*step*1000)
                    elif kind=='histogram':
                        step=definition['interval']; raw=number(raw)//step*step
                    choices.append(raw if isinstance(raw,list) else [raw])
                for key in itertools.product(*choices):
                    groups.setdefault(key,[]).append(doc)
            rows=[]; after=comp.get('after')
            ordered=lambda key:tuple('' if val is None else str(val) for val in key)
            for key in sorted(groups,key=ordered):
                if after is not None and ordered(key)<=ordered(tuple(after[name] for name in names)):
                    continue
                members=groups[key]
                rows.append({'key':dict(zip(names,key,strict=True)),'doc_count':len(members),
                             **{name:self.aggregate(sub,members) for name,sub in spec.get('aggs',{}).items()}})
            page=rows[:comp.get('size',1000)]
            return {'buckets':page, **({'after_key':page[-1]['key']} if page else {})}
        kind='date_histogram' if 'date_histogram' in spec else 'histogram'
        cfg=spec[kind]; step=int(cfg['fixed_interval'].rstrip('s')) if kind=='date_histogram' else cfg['interval']
        counts={}
        for doc in docs:
            stamp=number(value(doc['_source'],cfg['field']),cfg['field']); key=stamp//step*step
            counts[key]=counts.get(key,0)+1
        if cfg.get('extended_bounds'):
            low=number(cfg['extended_bounds']['min'])//step*step
            high=number(cfg['extended_bounds']['max'])
            while low<=high:
                counts.setdefault(low,0); low+=step
        return {'buckets':[{'key':key*1000 if kind=='date_histogram' else key,
                           'key_as_string':datetime.fromtimestamp(key,UTC).isoformat(),'doc_count':count}
                           for key,count in sorted(counts.items())]}
