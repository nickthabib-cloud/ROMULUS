"""Native ICS retrieval excludes exact polling reads and retains unknowns and exceptions."""
from __future__ import annotations

from dataclasses import dataclass, field

from romulus.evidence.ics_catalog import retrieval_selection
from romulus.evidence.zeek_catalog import PLAIN, SHAPES, ZEEK_LOGS, lookup_log
from romulus.hunt.zeek_sources import _marker_refused, native_field, source_groups
from romulus.sources.models import Predicate

SELECTION_NOTE = ('Routine read requests and responses were excluded at retrieval where verified native function fields permit it; '
    'ICS rules evaluated write, control, program-transfer, mode-change, restart and discovery functions '
    'and exceptions; requests whose function or subfunction is not typed are counted as not judged.')


@dataclass
class Selection:
    groups: list[list[Predicate]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    selected: bool = False


def selection(contract, profile):
    if contract is None:
        return Selection(reasons=['ICS retrieval is unfiltered: no field contract is available.'])
    logs=[log for log in ZEEK_LOGS if log.family=='ics_tx']
    plain=contract.zeek_sensor is not None
    if plain and contract.zeek_log and lookup_log(PLAIN,contract.zeek_log) not in logs:
        return Selection()
    inventory=profile.get('inventory') or []
    datasets=set(profile.get('datasets') or {})
    known_names={str(item.get('dataset')) for item in inventory if item.get('provider')=='zeek'}
    known_names.update(str(value).removeprefix('zeek:').removeprefix('zeek.') for value in datasets
                       if str(value).startswith(('zeek:','zeek.')))
    if plain and contract.zeek_log:
        known_names.add(contract.zeek_log)
    candidates=[log for log in logs if any(name in known_names for names in log.names.values() for name in names)]
    if not candidates and not plain:
        return Selection()
    if any(str(note).startswith('ds inventory truncated') for note in profile.get('notes') or []):
        return Selection(reasons=['ICS retrieval is unfiltered: dataset inventory is incomplete.'])
    candidates=candidates or logs
    groups=[]
    filtered_names=set()
    has_filter=False
    reasons=[]
    for log in candidates:
        if not plain:
            for item in inventory:
                if item.get('provider') not in (None,''):
                    continue
                dataset=item.get('dataset')
                shapes=(["security_onion"] if dataset in log.names.get("security_onion",())
                        else ["elastic","security_onion"] if any(dataset=='zeek.'+name
                            for shape in ("elastic","security_onion") for name in log.names.get(shape,())) else [])
                if any(not source_groups(contract,log,shape) for shape in shapes):
                    return Selection(reasons=[f'ICS retrieval is unfiltered: {log.name} has an unresolved native delivery shape or unmapped source marker.'])
        matched=False
        for shape in (PLAIN,) if plain else SHAPES:
            markers=source_groups(contract,log,shape)
            if not markers:
                policy=retrieval_selection(log.name,shape) if log.names.get(shape) else None
                if policy and (_marker_refused(contract,log,shape) or any(
                        native_field(contract,path,'exists') for path in policy.read_fields)):
                    return Selection(reasons=[f'ICS retrieval is unfiltered: {log.name} {shape} source markers are unmapped or not filterable.'])
                continue
            matched=True
            policy=retrieval_selection(log.name,shape)
            if not policy.read_fields:
                # A read-unfilterable log remains an unfiltered marker branch. Other logs on this target
                # retain their safe polling selectors; an absent inventory entry also passes the catch-all.
                if log.name in {'dnp3','dnp3_objects'}:
                    reasons.append(f'ICS retrieval is unfiltered for {log.name} {shape}: no safe indexed function/exception selection.')
                groups.extend(markers)
                continue
            reads=[native_field(contract,path,'not_in') for path in policy.read_fields]
            exceptions=[native_field(contract,path,'exists') for path in policy.exception_fields]
            nonzero=[native_field(contract,path,'not_in') for path in policy.nonzero_exception_fields]
            if not all(reads) or not all(exceptions) or not all(nonzero):
                return Selection(reasons=[f'ICS retrieval is unfiltered: {log.name} {shape} native function or exception field is unmapped or not filterable.'])
            row=[Predicate(field=path,op='not_in',value=list(policy.read_values)) for path in reads]
            has_filter=True
            for marker in markers:
                discriminator=native_field(contract,'_path' if plain else 'event.dataset','in')
                for predicate in marker:
                    if predicate.field==discriminator and predicate.op in {'in','eq'}:
                        filtered_names.update(predicate.value if predicate.op=='in' else [predicate.value])
                groups.append([*marker,*row])
                groups.extend([*marker,Predicate(field=path,op='exists')] for path in exceptions)
                for path in nonzero:
                    values = ([0] if contract.fields[path].type in {'long','integer','short'}
                              else ['0','0x00','0x0000','No error'])
                    groups.append([*marker,Predicate(field=path,op='not_in',value=values),
                                   Predicate(field=path,op='exists')])
        if not matched:
            return Selection(reasons=[f'ICS retrieval is unfiltered: {log.name} source markers are not filterable.'])
    if not groups:
        return Selection()
    if not has_filter:
        return Selection(reasons=reasons)
    if not (plain and contract.zeek_log):
        marker='_path' if plain else 'event.dataset'
        field=native_field(contract,marker,'not_in')
        if field is None:
            return Selection(reasons=['ICS retrieval is unfiltered: native dataset discriminator is not filterable.'])
        # Only names with actual polling-filter branches can be excluded here. New datasets appearing
        # after preflight, rollover or resume pass through, even when already known to the global catalog.
        groups.append([Predicate(field=field,op='not_in',value=sorted(filtered_names))])
        if not plain:
            # A non-Zeek producer may use an identical bare dataset. Keep it independent of Zeek filtering.
            provider=native_field(contract,'event.provider','not_in')
            if provider and contract.supports(provider,'exists') and contract.supports(provider,'missing'):
                groups.append([Predicate(field=provider,op='missing')])
                groups.append([Predicate(field=provider,op='exists'),
                               Predicate(field=provider,op='not_in',value=['zeek'])])
            else:
                return Selection(reasons=['ICS retrieval is unfiltered: records without a provider cannot be selected safely.'])
    return Selection(groups,[SELECTION_NOTE,*reasons],True)
