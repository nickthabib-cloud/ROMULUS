"""Pure bounded sensor-scoped gap context from already retrieved typed evidence."""
MAX_ROWS, MAX_KEYS = 10000, 1000
UID_FIELDS = ('zeek.uid', 'zeek.uids', 'file.conn_uids')
FILE_FIELDS = ('file.fuid', 'file.fuids', 'http.orig_fuids', 'http.resp_fuids')


def has_gap(event):
    return (event.get('conn.missed_bytes',0)>0 or any(char in str(event.get('conn.history','')).lower() for char in 'gx')
            or event.get('file.missing_bytes',0)>0 or event.get('file.overflow_bytes',0)>0
            or event.get('file.timedout') is True)


def _note(match,reason):
    if reason not in match.notes:
        match.notes.append(reason)


def _values(event,fields):
    for field in fields:
        value=event.get(field)
        for item in value if isinstance(value,list) else (value,):
            if item:
                yield str(item)


def _keys(match,events):
    keys={};count=0
    for event in events:
        sensor=event.get('observer.name')
        if not sensor:
            continue
        for kind,fields in (('uid',UID_FIELDS),('fuid',FILE_FIELDS)):
            for value in _values(event,fields):
                own=keys.setdefault(sensor,set());key=(kind,value)
                if key in own:
                    continue
                if count>=MAX_KEYS:
                    _note(match,'content-gap join key limit 1000 reached; remaining witnesses unresolved')
                    return keys
                own.add(key);count+=1
    return keys


def related(match,context):
    """Bounded sensor-scoped closure through files and their carrying connections."""
    selected={event.id:event for event in match.events[:MAX_ROWS] if event.get('observer.product')=='zeek'}
    pool={event.id:event for event in context[:MAX_ROWS] if event.get('observer.product')=='zeek'}
    if len(context)>MAX_ROWS or len(match.events)>MAX_ROWS:
        _note(match,'content-gap context row limit 10000 reached; remaining witnesses unresolved')
    for _ in range(3):
        keys=_keys(match,selected.values())
        before=len(selected)
        for event in pool.values():
            if event.id in selected or len(selected)>=MAX_ROWS:
                continue
            own=keys.get(event.get('observer.name'),set())
            if (any(('uid',value) in own for value in _values(event,UID_FIELDS)) or
                    any(('fuid',value) in own for value in _values(event,FILE_FIELDS))):
                selected[event.id]=event
        if len(selected)==before:
            break
    return list(selected.values())


def attach(match,context,*,limited=False):
    """Use already fetched witnesses without spending hidden publication-time queries."""
    if not any(event.get('observer.product')=='zeek' for event in match.events):
        return
    connected=related(match,context)
    gaps=[event for event in connected if has_gap(event)]
    existing={event.id for event in match.events}
    if gaps:
        # Clean files carry the FUID-to-UID edge and must be citable too.
        for event in connected:
            if event.id not in existing and (has_gap(event) or event.get('zeek.log')=='files'):
                match.events.append(event)
                match.context_ids.add(event.id)
                existing.add(event.id)
        for event in gaps:
            for caveat in event.caveats:
                _note(match,f'{caveat} (supporting record {event.id})')
    if limited and not any(event.get('zeek.log')=='conn' for event in connected):
        _note(match,'content-gap carrying connection not in fetched evidence; further truncation checks not assessed')
