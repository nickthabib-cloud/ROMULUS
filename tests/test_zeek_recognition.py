"""Which shipper wrote a Zeek record, over every catalogued log, every shipper shape and sparse or altered records.

A record read with another shipper's layout loses its sensor and uid and can change units (Security Onion writes a
duration in seconds where Elastic writes nanoseconds), so recognition must never guess: a record is read in the shape
whose markers it carries, or it is not read. The confusion matrix below names, for each way a record can arrive, what
it must be recognized as; the consequences test checks that every record that is read keeps its time units, sensor
and uid.
"""
import copy

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek import AMBIGUOUS, zeek_record
from romulus.evidence.zeek_catalog import ZEEK_LOGS
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl

# a zeek.<name> dataset only Elastic writes (Security Onion names no log so)
ELASTIC_ONLY = {"connection", "files", "signature"}


def written(log: str) -> dict:
    if log == "conn":
        return {shape: (lambda shape=shape: zf.WRITERS[shape](zf.FULL, f"{shape}-conn")) for shape in zf.SHAPES}
    return {shape: (lambda shape=shape: zl.WRITERS[shape](zl.ROWS[log], f"{shape}-{log}")) for shape in
            zl.shapes_of(log)}


def _drop(src: dict, path: str) -> None:
    *parents, last = path.split(".")
    cur = src
    for part in parents:
        cur = cur.get(part) if isinstance(cur, dict) else None
        if cur is None:
            return
    cur.pop(last, None)


def _set(src: dict, path: str, value) -> None:
    *parents, last = path.split(".")
    cur = src
    for part in parents:
        cur = cur.setdefault(part, {})
    cur[last] = value


VARIANTS = {
    "as-written": lambda s: None,
    "no-data_stream": lambda s: s.pop("data_stream", None),
    "no-data_stream.dataset": lambda s: _drop(s, "data_stream.dataset"),
    "no-event.module": lambda s: _drop(s, "event.module"),
    "module-zeek": lambda s: _set(s, "event.module", "zeek"),
    "datastream-zeek": lambda s: _set(s, "data_stream.dataset", "zeek"),
    "module+datastream-zeek": lambda s: (_set(s, "event.module", "zeek"), _set(s, "data_stream.dataset", "zeek")),
    "provider-zeek": lambda s: _set(s, "event.provider", "zeek"),
    "no-event.dataset": lambda s: _drop(s, "event.dataset"),
    "dataset-list": lambda s: _set(s, "event.dataset", [s["event"]["dataset"]]),
}


def expected(shape: str, variant: str, name: str) -> str | None:
    """What a record written in `shape` (its dataset naming `name`) must be recognized as after `variant`: a shape,
    AMBIGUOUS (never read), or None (not taken as Zeek: it keeps the path it took before Zeek was read)."""
    if shape == "malcolm":                       # its provider decides; without a dataset it is not Zeek
        return None if variant == "no-event.dataset" else "malcolm"
    if variant in ("no-event.dataset", "dataset-list"):
        # Elastic's data stream alone still names the stream; a list is no shipper's zeek.<log> dataset
        return "elastic" if shape == "elastic" and variant == "no-event.dataset" else None
    if variant == "module+datastream-zeek":
        return "security_onion"                  # Security Onion's two markers are its own, whatever else is written
    if shape == "security_onion":
        if variant in ("no-data_stream", "no-data_stream.dataset", "no-event.module"):
            return AMBIGUOUS
        return "security_onion"
    # Elastic: its data stream (or Filebeat's fileset) is its marker; without one only its own names are read
    if variant in ("no-data_stream", "no-data_stream.dataset", "datastream-zeek"):
        return "elastic" if name in ELASTIC_ONLY else AMBIGUOUS
    return "elastic"


CASES = [(log.name, shape, variant) for log in ZEEK_LOGS for shape in written(log.name) if shape != "plain"
         for variant in VARIANTS]


@pytest.mark.parametrize("log,shape,variant", CASES, ids=["-".join(case) for case in CASES])
def test_a_record_is_read_in_the_shape_whose_markers_it_carries_or_not_read(log, shape, variant):
    h = written(log)[shape]()
    dataset = h["_source"]["event"]["dataset"]
    name = dataset.removeprefix("zeek.") if isinstance(dataset, str) else dataset
    VARIANTS[variant](h["_source"])
    record = zeek_record(h["_source"])
    got = None if record is None else record.shape
    assert got == expected(shape, variant, name), (log, shape, variant, got)
    if got == AMBIGUOUS:
        assert record.log is None
        events, skips, errors = normalize_hits([h])
        assert events == [] and errors == [] and len(skips) == 1
        [reason] = skips
        assert reason.startswith(f"dataset:{dataset} is not normalized: ")     # counted as no rule's evaluation


UNIT_FIELDS = {"conn": "session.duration_s", "dns": "dns.rtt_s", "files": "file.duration_s",
               "snmp": "snmp.duration_s"}


@pytest.mark.parametrize("log", sorted(UNIT_FIELDS))
def test_every_record_read_in_its_own_shape_keeps_its_units_sensor_and_uid(log):
    for shape, make in written(log).items():
        if shape == "plain":
            continue
        truth = normalize_hits([make()])[0][0]
        for variant, mutate in VARIANTS.items():
            if variant == "module+datastream-zeek" and shape != "security_onion":
                continue                         # another shipper's markers forged onto a record
            h = make()
            mutate(h["_source"])
            record = zeek_record(copy.deepcopy(h["_source"]))
            if record is None or record.shape != shape:
                continue
            events, _skips, errors = normalize_hits([h])
            assert errors == [] and len(events) == 1, (shape, variant)
            event = events[0]
            field = UNIT_FIELDS[log]
            assert event.get(field) == truth.get(field), (shape, variant, field)
            assert (event.host, event.get("zeek.uid")) == (truth.host, truth.get("zeek.uid")), (shape, variant)
