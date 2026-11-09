"""Catalog-derived, sensor-scoped Zeek source predicates shared by bounded readers."""
from dataclasses import dataclass
from functools import lru_cache
from math import floor

from romulus.evidence.zeek import _ELASTIC_ONLY
from romulus.evidence.zeek_catalog import (
    ELASTIC,
    MALCOLM,
    PLAIN,
    SECURITY_ONION,
    SHAPES,
    ZEEK_LOGS,
    lookup_log,
)
from romulus.sources.models import Predicate, SearchIntent, Window, typed_field_name
from romulus.sources.profile import native_field as exact_native_field


def native_field(contract, path, op='eq'):
    if path.startswith('original:'):
        return None
    path = path.removesuffix(':ns').removesuffix(':ms')
    return exact_native_field(contract, path, op)


def overlap_groups(contract, groups, start, partition_end, *, shape=None):
    """A safe superset using the selected delivery's verified duration units."""
    if shape == MALCOLM:
        field = native_field(contract,'lastPacket','gte')
        if field and contract.supports(field,'missing'):
            value = (start.isoformat() if contract.fields[field].type.startswith('date')
                     else start.timestamp()*1000)
            return [[*group,Predicate(field=field,op=op,value=value if op=='gte' else None)]
                    for group in groups for op in ('gte','missing')]
    fields = {}
    for log in ZEEK_LOGS:
        if log.name != 'conn':
            continue
        for delivery in (shape,) if shape else SHAPES:
            for path in log.spec('session.duration_s').paths.get(delivery, ()):
                field = native_field(contract,path,'gte')
                if field and contract.supports(field,'missing'):
                    factor = 1e9 if path.endswith(':ns') else 1000 if path.endswith(':ms') else 1
                    fields.setdefault(field,[]).append(factor)
    if fields:
        field,factors = next(iter(fields.items()))
        # An unscoped caller gets the least restrictive verified unit conversion.
        duration = max(0,(start-partition_end).total_seconds())*min(factors)
        if contract.fields[field].type in {'long', 'integer', 'short'}:
            # A truncated stored duration can be below the true overlap threshold by less than one unit.
            duration = floor(duration)
        return [[*group,Predicate(field=field,op=op,value=duration if op=='gte' else None)]
                for group in groups for op in ('gte','missing')]
    return groups


def zeek_capable(contract):
    """Explicit native declaration or verified Zeek-specific mapped fields."""
    return bool(contract and (contract.zeek_sensor or any(name.startswith('zeek.') or name=='log.id.uid'
                                                          for name in contract.fields)))


class _Markers:
    """A contract whose `supports` resolves catalog paths to the target's exact-capable fields."""
    def __init__(self, contract):
        self._contract = contract

    def __getattr__(self, name):
        return getattr(self._contract, name)

    def supports(self, path, op):
        return native_field(self._contract, path, op) is not None


def source_groups(contract, log, shape, *, widened=None):
    """Use only exact capabilities actually reported by the source contract. `widened`, when a list, receives the
    exclusion markers the target maps but cannot search as absent (`widened_markers`)."""
    return [[Predicate(field=native_field(contract, predicate.field, predicate.op), op=predicate.op,
                       value=predicate.value)
             for predicate in group] for group in _source_groups(_Markers(contract), log, shape, widened)]


def widened_markers(contract, log, shape):
    """The fields that keep other delivery layouts' rows out of this layout's source groups, which the target maps
    but cannot search as absent: a name no predicate can carry (`zeek.dns.@proc`), or a mapping type without an
    absence search. Without them the groups select a superset of the layout's rows. A raw read of that superset
    stays exact, since each record's layout is recognized from the record itself (evidence.zeek.zeek_record); an
    aggregate over it is not, since it counts the other layouts' rows as this one's."""
    widened = []
    _source_groups(_Markers(contract), log, shape, widened)
    return list(dict.fromkeys(widened))


def widened_reason(target, log, shape, fields):
    """Why a layout's aggregate for `log` is not run, naming a bounded number of the fields (untrusted names, quoted
    and clipped)."""
    def few(names):
        shown = ', '.join(repr(name[:80]) for name in names[:3])
        return shown + (f' and {len(names)-3} more' if len(names) > 3 else '')
    untyped = sorted(name for name in fields if not typed_field_name(name))
    untyped_set = set(untyped)
    typed = sorted(name for name in fields if name not in untyped_set)
    causes = ([f'source field name {few(untyped)} not expressible as a typed predicate'] if untyped else []) + (
        [f'source field {few(typed)} cannot be searched as absent'] if typed else [])
    return (f"{target}: Zeek {log.name} {shape} selection cannot exclude other layouts' rows "
            f"({'; '.join(causes)}); visibility unresolved")


def _source_groups(contract, log, shape, widened=None):
    def exclude(group, field):
        """Add an absence marker; a mapped marker that cannot be searched as absent is reported as widening."""
        if typed_field_name(field) and contract.supports(field, 'missing'):
            group.append(Predicate(field=field, op='missing'))
        elif widened is not None and field in contract.fields:
            widened.append(field)

    names = sorted(log.names.get(shape, ()))
    if not names:
        return []
    if shape == PLAIN:
        if not getattr(contract, 'zeek_sensor', None):
            return []
        declared = getattr(contract, 'zeek_log', None)
        if declared:
            return [[]] if lookup_log(PLAIN,declared) == log else []
        return [[Predicate(field='_path', op='in', value=names)]] if contract.supports('_path', 'in') else []
    if shape == MALCOLM and contract.supports('event.provider', 'eq') and contract.supports('event.dataset', 'in'):
        return [[Predicate(field='event.provider', op='eq', value='zeek'),
                 Predicate(field='event.dataset', op='in', value=names)]]
    if shape == ELASTIC:
        groups=[]
        for name in names:
            dataset='zeek.'+name
            if contract.supports('data_stream.dataset','eq'):
                marker=[Predicate(field='data_stream.dataset',op='eq',value=dataset)]
                if contract.supports('event.dataset','eq'):
                    groups.append([*marker,Predicate(field='event.dataset',op='eq',value=dataset)])
                    groups.append([*marker,Predicate(field='event.dataset',op='missing')])
                else:
                    groups.append(marker)
            if all(contract.supports(field,'eq') for field in ('fileset.name','event.module','event.dataset')):
                marker=[Predicate(field='event.module',op='eq',value='zeek'),
                        Predicate(field='fileset.name',op='eq',value=name),
                        Predicate(field='event.dataset',op='eq',value=dataset)]
                exclude(marker,'data_stream.dataset')
                groups.append(marker)
            if name in _ELASTIC_ONLY and contract.supports('event.dataset','eq'):
                marker=[Predicate(field='event.dataset',op='eq',value=dataset)]
                if 'data_stream.dataset' in contract.fields:
                    if not contract.supports('data_stream.dataset','missing'):
                        continue
                    marker.append(Predicate(field='data_stream.dataset',op='missing'))
                if 'event.provider' in contract.fields:
                    if contract.supports('event.provider','missing'):
                        groups.append([*marker,Predicate(field='event.provider',op='missing')])
                    if contract.supports('event.provider','eq'):
                        groups.append([*marker,Predicate(field='event.provider',op='eq',value='zeek')])
                else:
                    groups.append(marker)
        return groups
    if shape == SECURITY_ONION and contract.supports('event.module', 'eq') and contract.supports('event.dataset', 'in'):
        marker=[Predicate(field='event.module',op='eq',value='zeek')]
        exclude(marker,'event.provider')
        groups=[]
        if contract.supports('data_stream.dataset','eq'):
            groups.append([*marker,Predicate(field='data_stream.dataset',op='eq',value='zeek'),
                           Predicate(field='event.dataset',op='in',value=names+['zeek.'+name for name in names])])
        bare=[*marker,Predicate(field='event.dataset',op='in',value=names)]
        # A source field name is never itself a predicate: only a field the contract supports becomes one (`exclude`).
        objects=tuple('zeek.'+logname+'.' for logname in names)
        for field in ('node','firstPacket',*[name for name in contract.fields if name.startswith(objects)]):
            exclude(bare,field)
        groups.append(bare)
        return groups
    return []


def sensor_groups(contract, log, shape, sensor):
    if shape == PLAIN:
        return [[]] if getattr(contract, 'zeek_sensor', None) == sensor else []
    groups = []
    previous = []
    for path in log.sensor_paths.get(shape, ()):
        field = native_field(contract, path)
        if field:
            groups.append([*previous, Predicate(field=field, op='eq', value=sensor)])
            if contract.supports(field, 'missing'):
                previous = [*previous, Predicate(field=field, op='missing')]
            else:
                break
    return groups


@lru_cache(maxsize=256)
def _unique_paths(log,shape):
    own={path for spec in log.fields for path in spec.paths.get(shape,())}
    others={path for item in ZEEK_LOGS if item is not log for spec in item.fields for path in spec.paths.get(shape,())}
    return own-others


@lru_cache(maxsize=256)
def _layout_paths(log,shape):
    own={path for spec in log.fields for path in spec.paths.get(shape,())}
    other={path for spec in log.fields for candidate in SHAPES if candidate!=shape
           for path in spec.paths.get(candidate,())}
    return {path.removesuffix(':ns').removesuffix(':ms') for path in own-other if path.startswith('zeek.')}


def _relevant(contract,log,shape,typed_fields,sensor):
    if not any(spec.typed in typed_fields and shape in spec.paths for spec in log.fields):
        return False
    if shape==PLAIN:
        if contract.zeek_sensor!=sensor:
            return False
        if contract.zeek_log:
            return lookup_log(PLAIN,contract.zeek_log) is log
    if shape==ELASTIC and 'agent.name' not in contract.fields:
        # Shared zeek.files/conn aliases alone cannot establish an Elastic target.
        layout=_layout_paths(log,shape)
        if not any(spec.native in layout for spec in contract.fields.values()):
            return False
    if shape==SECURITY_ONION and not any(name.startswith('log.id.') or name=='observer.name' for name in contract.fields):
        return False
    obj=log.log_objects.get(shape)
    if obj and any(name.startswith(obj+'.') for name in contract.fields):
        return True
    paths={path for spec in log.fields if spec.typed in typed_fields for path in spec.paths.get(shape,())}
    return any(native_field(contract,path,'exists') for path in paths|_unique_paths(log,shape))


def _marker_refused(contract,log,shape):
    """A mapped recognition pattern exists, but its exact marker cannot be searched."""
    if shape==PLAIN:
        patterns=[('_path',)] if contract.zeek_sensor and not contract.zeek_log else []
    elif shape==MALCOLM:
        patterns=[('event.provider','event.dataset')]
    elif shape==SECURITY_ONION:
        patterns=[('event.module','event.dataset')]
    else:
        patterns=[('data_stream.dataset',),('event.dataset','event.module','fileset.name')]
        if set(log.names.get(ELASTIC,())) & _ELASTIC_ONLY:
            patterns.append(('event.dataset',))
    return any(all(native_field(contract,path,'exists') for path in fields) and
               any(not native_field(contract,path,'eq') for path in fields) for fields in patterns)


@dataclass
class KeyPlan:
    intents: list
    reasons: list[str]


def key_intents(contracts, logs, sensor, typed_fields, values, window, *, limit=10000):
    """One bounded OR query per target, with marker, sensor and key on each branch."""
    values = sorted(set(values))
    if not sensor or not values:
        return KeyPlan([],[])
    intents = []
    reasons=[]
    for target, contract in sorted(contracts.items()):
        groups = []
        for log in logs:
            for shape in SHAPES:
                sources = source_groups(contract, log, shape)
                sensors = sensor_groups(contract, log, shape, sensor)
                if not sources:
                    if _marker_refused(contract,log,shape) and _relevant(contract,log,shape,typed_fields,sensor):
                        reason=f'{target}: Zeek {log.name} source markers not searchable; target join unresolved'
                        if reason not in reasons:
                            reasons.append(reason)
                    continue
                fields = {field for spec in log.fields if spec.typed in typed_fields
                          for path in spec.paths.get(shape, ())
                          if (field := native_field(contract, path, 'in')) is not None}
                if (not sensors or not fields) and _relevant(contract,log,shape,typed_fields,sensor):
                    reason=f'{target}: Zeek {log.name} '+('sensor' if not sensors else 'join key')+' not searchable; target join unresolved'
                    if reason not in reasons:
                        reasons.append(reason)
                for field in sorted(fields):
                    groups.extend([*source, *scope, Predicate(field=field, op='in', value=values)]
                                  for source in sources for scope in sensors)
        if groups:
            intents.append(SearchIntent(kind='raw', target=target,
                window=Window(start=window.start, end=window.end), any_of=groups, max_records=limit,
                purpose='expansion:zeek'))
    return KeyPlan(intents,reasons)
