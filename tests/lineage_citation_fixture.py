"""Source-backed lineage citations for tests whose typed events are synthetic fixtures."""
from romulus.detect.host import bind_lineage_citation_loader
from romulus.detect.observed import pointer_body
from romulus.evidence.typed import RawRef


def source_copies(events) -> dict[str, dict]:
    """Stable stand-in source documents for every raw reference on synthetic typed events."""
    return {
        ref.key: {"fixture.event_id": event.id, "fixture.raw_key": ref.key}
        for event in events
        for ref in event.raw
    }


def bind_lineage(rule, events) -> dict[str, dict]:
    """Bind source copies and a verified-loader stand-in to a rule used outside a Sweep."""
    events = list(events)
    raw = source_copies(events)
    by_ref = {ref.key: event for event in events for ref in event.raw}

    def load(pointers):
        selected, copies = {}, {}
        for event_id, blob in pointers.items():
            body = pointer_body(blob)
            records = [] if body is None else body.get("records", [])
            keys = [f"{index}/{native_id}" for index, native_id in records]
            if not keys or any(key not in by_ref for key in keys):
                continue
            event = by_ref[keys[0]].model_copy(deep=True)
            event.id = event_id
            event.raw = [RawRef(target=index, native_id=native_id) for index, native_id in records]
            if body["kind"] == "observed":
                event.family = "process_observed"
            selected[event_id] = event
            copies.update({key: raw[key] for key in keys})
        return selected, copies

    rule.bind_raw(raw, "fixture-target")
    bind_lineage_citation_loader([rule], load)
    return raw
