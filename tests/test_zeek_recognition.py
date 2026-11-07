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
from tests.fixtures import zeek_ics as zi
from tests.fixtures import zeek_logs as zl

# a zeek.<name> dataset only Elastic writes (Security Onion names no log so)
ELASTIC_ONLY = {"connection", "files", "signature", "smb_cmd", "known_hosts", "known_services", "known_certs", "capture_loss", "stats"}
# Elastic streams whose documents keep no zeek.<stream> object (their pipelines index only the columns they rename):
# with Security Onion 2.3's markers forged onto one, nothing tells it from a Security Onion record, which is then read
# as one (and these logs are no log of Security Onion's catalog: a counted skip)
ELASTIC_WITHOUT_OBJECT = {"known_hosts", "known_services", "known_certs"}


def written(log: str) -> dict:
    if log in zi.ROWS:
        return {shape: (lambda shape=shape: zi.hit(zi.ROWS[log], shape, f"{shape}-{log}"))
                for shape in zi.SHAPES_BY_LOG[log]}
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


def _security_onion_2_3(src: dict) -> None:
    """Security Onion 2.3's layout: its Filebeat inputs' module and bare dataset fields, renamed to event.module and
    event.dataset by its common pipeline (not prefixed), and no data stream (salt/filebeat/etc/filebeat.yml,
    salt/elasticsearch/files/ingest/common)."""
    src.pop("data_stream", None)
    _set(src, "event.module", "zeek")
    dataset = src["event"]["dataset"]
    _set(src, "event.dataset", dataset.removeprefix("zeek.") if isinstance(dataset, str) else dataset)


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
    "security-onion-2.3": _security_onion_2_3,
    "no-event.provider": lambda s: _drop(s, "event.provider"),
    "no-event.provider+module-zeek": lambda s: (_drop(s, "event.provider"), _set(s, "event.module", "zeek")),
}
# the logs whose Malcolm rows carry event.module "zeek" as written (1200_zeek_mutate.conf)
MALCOLM_MODULE = {"notice", "signatures"}


def expected(shape: str, variant: str, name: str) -> str | None:
    """What a record written in `shape` (its dataset naming `name`) must be recognized as after `variant`: a shape,
    AMBIGUOUS (never read), or None (not taken as Zeek: it keeps the path it took before Zeek was read)."""
    if shape == "malcolm" and variant.startswith("no-event.provider"):
        # Malcolm's own fields (node, firstPacket, zeek.<log>) with the module but no provider: never read as
        # Security Onion's; without the module the record keeps the path it took before
        module = variant.endswith("module-zeek") or (isinstance(name, str) and name in MALCOLM_MODULE)
        return AMBIGUOUS if module else None
    if shape == "malcolm":                       # its provider decides; without a dataset it is not Zeek
        # (a dataset that is already a list, Malcolm's smb_cmd with its referenced file, nested in another list is no
        # log name)
        nested = variant == "dataset-list" and isinstance(name, list)
        return None if variant == "no-event.dataset" or nested else "malcolm"
    if variant == "no-event.provider":
        variant = "as-written"                   # no other shipper writes the provider
    elif variant == "no-event.provider+module-zeek":
        variant = "module-zeek"
    if variant in ("no-event.dataset", "dataset-list"):
        # Elastic's data stream alone still names the stream; a list is no shipper's zeek.<log> dataset
        return "elastic" if shape == "elastic" and variant == "no-event.dataset" else None
    if variant == "security-onion-2.3" and shape == "elastic":
        # 2.3's markers on a record with Elastic's zeek.<stream> object; without one, a Security Onion record
        return "security_onion" if name in ELASTIC_WITHOUT_OBJECT else AMBIGUOUS
    if variant in ("module+datastream-zeek", "security-onion-2.3"):
        return "security_onion"                  # Security Onion's markers are its own, whatever else is written
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
        carried = h["_source"]["event"]["dataset"]                                  # as the variant left it
        assert reason.startswith(f"dataset:{carried} is not normalized: ")     # counted as no rule's evaluation


UNIT_FIELDS = {"conn": "session.duration_s", "dns": "dns.rtt_s", "files": "file.duration_s", "dce_rpc": "rpc.rtt_s",
               "snmp": "snmp.duration_s", "dhcp": "dhcp.duration_s"}


@pytest.mark.parametrize("log", sorted(UNIT_FIELDS))
def test_every_record_read_in_its_own_shape_keeps_its_units_sensor_and_uid(log):
    for shape, make in written(log).items():
        if shape == "plain":
            continue
        truth = normalize_hits([make()])[0][0]
        for variant, mutate in VARIANTS.items():
            if variant in ("module+datastream-zeek", "security-onion-2.3") and shape != "security_onion":
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


def _values(event) -> dict:
    return {"family": event.family, "ts": event.ts, "host": event.host, "caveats": event.caveats,
            "fields": {name: value.value for name, value in event.fields.items()}}


@pytest.mark.parametrize("log", [log.name for log in ZEEK_LOGS if "security_onion" in written(log.name)])
def test_security_onion_2_3_records_are_read_as_security_onion_2_4_records_are(log):
    """Security Onion 2.3 ships Zeek with Filebeat inputs that set event.module "zeek" and the bare log name, and no
    data stream; its Zeek pipelines are 2.4's, so a 2.3 record types exactly as the same 2.4 record does."""
    h = written(log)["security_onion"]()
    old = copy.deepcopy(h)
    _security_onion_2_3(old["_source"])
    record = zeek_record(old["_source"])
    assert (record.shape, record.origin, record.recognized_by) == ("security_onion", "event.dataset", "event.module")
    [new_event], [old_event] = normalize_hits([h])[0], normalize_hits([old])[0]
    assert _values(old_event) == _values(new_event)


@pytest.mark.parametrize("log", ["notice", "signatures"])
def test_malcolms_rows_that_carry_event_module_are_still_malcolms(log):
    """Malcolm writes event.provider "zeek" on every Zeek row and adds event.module "zeek" to notice and signatures
    rows (logstash/pipelines/zeek/1200_zeek_mutate.conf): the provider decides, read before the module."""
    h = zl.malcolm(zl.ROWS[log], f"mc-module-{log}")
    assert h["_source"]["event"]["module"] == "zeek" and h["_source"]["event"]["provider"] == "zeek"
    record = zeek_record(h["_source"])
    assert (record.shape, record.recognized_by) == ("malcolm", "event.provider")
    [event] = normalize_hits([h])[0]
    assert event.get("zeek.log") == log and event.host == zl.SENSOR

@pytest.mark.parametrize('name',sorted(ELASTIC_ONLY))
@pytest.mark.parametrize('mapped_stream',[False,True])
def test_exclusive_dataset_source_predicates_follow_existing_recognition(name,mapped_stream):
    from romulus.evidence.zeek_catalog import lookup_log
    from romulus.hunt.zeek_sources import source_groups
    from romulus.sources.compile import build_query
    from romulus.sources.models import SearchIntent, Window
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import matches

    log=lookup_log('elastic',name);hit=written(log.name)['elastic']()
    original=NativePivot('elastic',[hit]).contracts['network']
    hit['_source'].pop('data_stream')
    contract=NativePivot('elastic',[hit]).contracts['network']
    if mapped_stream:
        contract.fields['data_stream.dataset']=original.fields['data_stream.dataset']
    record=zeek_record(hit['_source'])
    assert record.shape=='elastic' and record.log is log
    event=normalize_hits([hit])[0][0]
    from datetime import timedelta
    groups=source_groups(contract,log,'elastic')
    assert groups
    intent=SearchIntent(kind='raw',target='network',window=Window(start=event.ts-timedelta(seconds=1),
        end=event.ts+timedelta(seconds=1)),any_of=groups)
    assert matches(build_query(intent,contract),hit['_source'])


@pytest.mark.parametrize('variant',['ambiguous_http','suricata_provider','arkime_provider','so_precedence','zeek_provider'])
def test_exclusive_source_branch_preserves_recognition_precedence(variant):
    from datetime import timedelta

    from romulus.evidence.zeek_catalog import CONN, HTTP
    from romulus.hunt.zeek_sources import source_groups
    from romulus.sources.compile import build_query
    from romulus.sources.models import SearchIntent, Window
    from tests.test_zeek_links import NativePivot
    from tests.zeek_source_support import matches

    hit=zl.elastic(zl.HTTP,'http') if variant=='ambiguous_http' else zf.elastic(zf.FULL,'conn')
    event=normalize_hits([hit])[0][0];log=HTTP if variant=='ambiguous_http' else CONN
    hit['_source'].pop('data_stream')
    if variant.endswith('_provider'):
        hit['_source']['event']['provider']=variant.removesuffix('_provider')
    if variant=='so_precedence':
        hit['_source']['event']['module']='zeek';hit['_source']['data_stream']={'dataset':'zeek'}
    contract=NativePivot('elastic',[hit]).contracts['network'] if variant=='zeek_provider' else None
    if contract is None:
        from romulus.sources.profile import contract_from_types
        from tests.test_zeek_links import types_of
        contract=contract_from_types('network',types_of(hit['_source']),role='network')
    groups=source_groups(contract,log,'elastic')
    selected=bool(groups) and matches(build_query(SearchIntent(kind='raw',target='network',
        window=Window(start=event.ts-timedelta(seconds=1),end=event.ts+timedelta(seconds=1)),any_of=groups),contract),hit['_source'])
    record=zeek_record(hit['_source'])
    assert selected==(variant=='zeek_provider')
    assert (record is not None and record.shape=='elastic')==selected
