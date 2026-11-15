"""Every dataset of a Linux host target is either read and evaluated by the sweep, or stated with its count and reason.

The sweep counts each dataset's records in the hunt window before retrieval and tallies what its partitions actually
retrieved. A dataset the plan selected whose window records were not all returned is stated with the shortfall, makes
the hunt partial and leaves the rules reading its families partial on that target. All records are synthetic.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from romulus.hunt import sweep as sw
from romulus.sources.profile import OPS_BY_TYPE, build_profile, contract_from_types
from tests import throughput_fixture as tf
from tests.test_linux_text_reporting import ProfileClient, _sample

# A Filebeat-loaded host index: current Beats templates map `message` as match_only_text and `event.original` as a
# keyword with neither an index nor doc values, and a plain log or filestream input fills only `message`.
REAL_MAPPING = {"logs": {"mappings": {"properties": {
    "@timestamp": {"type": "date"},
    "message": {"type": "match_only_text"},
    "event": {"properties": {"dataset": {"type": "keyword"},
                             "original": {"type": "keyword", "index": False, "doc_values": False}}},
    "input": {"properties": {"type": {"type": "keyword"}}},
    "log": {"properties": {"file": {"properties": {"path": {"type": "keyword"}}}}},
}}}}
FILEBEAT_TYPES = {**tf.HOST_TYPES, "message": "match_only_text", "event.original": "keyword:not_indexed",
                  "input.type": "keyword", "log.file.path": "keyword"}
DNSMASQ = ["Nov 18 14:00:01 dnsmasq[123]: query[A] update.example from 10.0.0.5",
           "Nov 18 14:00:01 dnsmasq[123]: forwarded update.example to 192.0.2.53",
           "Nov 18 14:00:02 dnsmasq[123]: reply update.example is 203.0.113.9"]
HORDE = ["2024-11-18T14:00:04+00:00 INFO: HORDE [imp] Login success for alice"]
APP = ["Nov 18 14:00:05 web1 custom-app[7]: started"]


def _docs(datasets, *, offset=timedelta(0), without_payload=()):
    builder = tf.Builder(5)
    n = 0
    for dataset, lines in datasets.items():
        for line in lines:
            n += 1
            builder._doc("web1", tf.T0 + offset + timedelta(seconds=n), dataset, None, message=line,
                         input={"type": "log"}, log={"file": {"path": f"/var/log/{dataset}"}})
    for dataset in without_payload:
        n += 1
        builder._doc("web1", tf.T0 + offset + timedelta(seconds=n), dataset, None, input={"type": "log"},
                     log={"file": {"path": f"/var/log/{dataset}"}}, application={"state": "healthy"})
    return {tf.HOST_TARGET: builder.host, tf.NETWORK_TARGET: [], tf.ARKIME_TARGET: []}


def _profile(types, datasets, *, extra_inventory=None):
    """The preflight profile build_profile writes for this index: real inventory, real bounded samples."""
    inventory = {name: len(lines) for name, lines in datasets.items()}
    inventory.update(extra_inventory or {})
    # preflight samples the inventory in name order
    lines_of = {**{name: [] for name in extra_inventory or {}}, **datasets}
    samples = [_sample(lines_of[name], name, total=None if lines_of[name] else inventory[name])
               for name in sorted(inventory)]
    client = ProfileClient(inventory, [*samples, _sample([], "", total=0)], fields=dict(types))
    profile, _contract = build_profile(client, "logs")
    data = profile.model_dump(mode="json")
    data.update(target=tf.HOST_TARGET, id="host-profile")
    return data


def _run(tmp_path, monkeypatch, types, datasets, *, docs=None, profile=None):
    with monkeypatch.context() as patch:
        tf.patched_sizes(patch)
        patch.setattr(tf, "HOST_TYPES", types)
        snapshot = tf.run_stack(tmp_path, docs=docs or _docs(datasets),
                                profiles={tf.HOST_TARGET: profile or _profile(types, datasets)})
    summary = next(row["detail"] for row in snapshot["audit"] if row["action"] == "hunt.sweep_summary")
    rows = [row for row in snapshot["manifest"]["coverage"]["not_assessed"] if row["target"] == tf.HOST_TARGET]
    return snapshot, summary, rows


def _reconciliation_cells(snapshot):
    return [row for row in snapshot["rule_cells"] if row["partition"] == sw.DATASET_RECONCILIATION_PARTITION]


def test_match_only_text_payload_is_presence_searchable():
    assert OPS_BY_TYPE["match_only_text"] == {"exists", "missing"}
    contract = contract_from_types("logs", FILEBEAT_TYPES)
    assert contract.supports("message", "exists")


def test_filebeat_text_datasets_are_retrieved_and_evaluated_or_stated(tmp_path, monkeypatch):
    """(i) a text dataset the product normalizes and (ii) one it does not are both retrieved: the first becomes typed
    events, the second is a counted skip naming its dataset. Nothing is stated as missed."""
    datasets = {"dnsmasq.log": DNSMASQ, "horde.log": HORDE}
    snapshot, summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets)
    stats = snapshot["stats"]
    assert stats["records"] == 4
    assert stats["linux_shapes"][tf.HOST_TARGET] == {"linux.text:dnsmasq.log": 3}
    assert stats["events"] == 3                          # every dnsmasq line typed; the horde line is a counted skip
    assert stats["skips"] == {"text line in no recognized format: horde.log": 1}
    assert "dataset_reconciliation" not in stats
    assert not _reconciliation_cells(snapshot)
    assert not [row for row in rows if row["records"]]     # nothing on the target is stated as unread
    skipped = [row for row in snapshot["manifest"]["coverage"]["not_assessed"] if row["records"]]
    assert [(row["dataset"], row["records"]) for row in skipped] == [("horde.log", 1)]
    assert not any("were not retrieved" in reason for reason in summary["partial_reasons"])


def test_records_without_the_payload_of_a_selected_dataset_are_stated_with_count(tmp_path, monkeypatch):
    """(iii) the sample showed a text payload, so the dataset was selected; records of it without the payload are not
    returned by the content selection. They are stated with the exact shortfall, and the hunt is partial."""
    datasets = {"custom.app": APP}
    docs = _docs(datasets, without_payload=["custom.app", "custom.app"])
    snapshot, summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets, docs=docs)
    [row] = [row for row in rows if row["dataset"] == "custom.app"]
    assert row["records"] == 2
    assert row["count_scope"] == "records in the hunt window by @timestamp that the sweep did not retrieve, of 3"
    assert row["reason"].startswith("not retrieved: selected for retrieval")
    assert any("custom.app (2)" in reason for reason in summary["partial_reasons"])
    cells = _reconciliation_cells(snapshot)
    assert cells and all(cell["state"] == "evaluated_partial" and cell["target"] == tf.HOST_TARGET for cell in cells)
    assert {"auth.password_guessing", "net.dns_nxdomain_burst"} <= {cell["rule_id"] for cell in cells}
    assert "host.kernel_module_load" not in {cell["rule_id"] for cell in cells}   # reads no text family
    from romulus.detect.registry import fresh_pack
    oses = {pb.id: set(pb.os_families) for pb in fresh_pack()}
    # a Linux target's shortfall leaves no Windows-only rule partial
    assert all(oses[cell["rule_id"]] & {"linux", "unknown"} for cell in cells)


def test_dataset_whose_sample_has_no_payload_is_stated_with_count(tmp_path, monkeypatch):
    """(iii) literally: the bounded sample of a dataset shows no text payload, so it is not selected; the report names
    it with its count and the sample reason, and the sweep's window count names nothing twice."""
    datasets = {"dnsmasq.log": DNSMASQ}
    docs = _docs(datasets, without_payload=["custom.state", "custom.state"])
    profile = _profile(FILEBEAT_TYPES, datasets, extra_inventory={"custom.state": 2})
    snapshot, _summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets, docs=docs, profile=profile)
    [row] = [row for row in rows if row["dataset"] == "custom.state"]
    assert row["records"] == 2 and row["reason"] == "not retrieved: sample incomplete"
    assert snapshot["stats"]["records"] == 3 and not _reconciliation_cells(snapshot)


def test_reconciliation_rows_render_counts_zero_and_not_counted():
    from romulus.report.manifest import publish_revision
    from romulus.report.markdown import render
    from tests.test_report import _repo_with_finding

    repo, _ = _repo_with_finding()
    manifest = publish_revision(repo, "h1", "test")
    manifest["coverage"]["not_assessed"] = [
        {"target": "logs", "dataset": "dnsmasq.log", "records": 0, "reason": "selected for retrieval, but none",
         "count_scope": "records in the hunt window by @timestamp; the whole index held 3 at source preflight"},
        {"target": "logs", "dataset": "horde.log", "records": None, "reason": "not retrieved: selected",
         "count_scope": "not counted: the hunt window's records were not counted by dataset"},
        {"target": "logs", "dataset": "(records naming no dataset)", "records": 4, "reason": "not retrieved by the sweep",
         "count_scope": "records in the hunt window by @timestamp"}]
    section = render(manifest).split("### Data not assessed", 1)[1].split("###", 1)[0]
    assert "| logs | dnsmasq.log | 0 | records in the hunt window by @timestamp; the whole index held 3" in section
    assert "| logs | horde.log | unknown | not counted: the hunt window's records were not counted" in section
    assert "| logs | (records naming no dataset) | 4 |" in section


def test_payload_mapped_in_an_unsearchable_type_is_stated_not_silent(tmp_path, monkeypatch):
    """The text payload is mapped in a type the source cannot test for presence: the content selection cannot reach
    the records, which are stated with their counts and the mapping reason."""
    types = {**FILEBEAT_TYPES, "message": "semantic_text", "event.original": "keyword"}
    datasets = {"dnsmasq.log": DNSMASQ, "horde.log": HORDE}
    snapshot, summary, rows = _run(tmp_path, monkeypatch, types, datasets)
    assert snapshot["stats"]["records"] == 0
    stated = {row["dataset"]: row for row in rows if row["dataset"] in datasets}
    assert {name: row["records"] for name, row in stated.items()} == {"dnsmasq.log": 3, "horde.log": 1}
    assert all("message is mapped as semantic_text" in row["reason"] for row in stated.values())
    assert any("dnsmasq.log (3), horde.log (1)" in reason for reason in summary["partial_reasons"])
    assert _reconciliation_cells(snapshot)


def test_dataset_indexed_outside_the_window_is_named_with_its_index_count(tmp_path, monkeypatch):
    """Records indexed at the time they were shipped fall outside the window they describe: none is in the window,
    so nothing was missed there, but the dataset is named with its whole-index count rather than left silent."""
    datasets = {"dnsmasq.log": DNSMASQ}
    docs = _docs(datasets, offset=timedelta(days=400))
    snapshot, summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets, docs=docs)
    [row] = [row for row in rows if row["dataset"] == "dnsmasq.log"]
    assert row["records"] == 0
    assert row["count_scope"] == "records in the hunt window by @timestamp; the whole index held 3 at source preflight"
    assert "shipped rather than the time they were logged" in row["reason"]
    assert not _reconciliation_cells(snapshot)          # no window record went unread
    assert not any("were not retrieved" in reason for reason in summary["partial_reasons"])


def test_window_records_of_a_dataset_the_inventory_never_listed_are_named(tmp_path, monkeypatch):
    """A dataset absent from the preflight inventory (it grew after preflight, or the inventory was truncated) whose
    window records the sweep did not select is named with its window count."""
    datasets = {"dnsmasq.log": DNSMASQ}
    docs = _docs({**datasets, "late.json": ["{}"]})
    for row in docs[tf.HOST_TARGET]:
        if row["_source"]["event"]["dataset"] == "late.json":
            row["_source"].pop("message")
            row["_source"].pop("input")
            row["_source"].pop("log")
    snapshot, _summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets, docs=docs)
    [row] = [row for row in rows if row["dataset"] == "late.json"]
    assert row["records"] == 1 and row["count_scope"] == "records in the hunt window by @timestamp"
    assert not _reconciliation_cells(snapshot)          # never selected: listed, not a partial selection


def test_unknown_window_count_states_selected_text_dataset_as_not_counted(tmp_path, monkeypatch):
    """When the window cannot be counted by dataset, a selected text dataset with no retrieved record is stated as
    not counted, and its rules stay partial."""
    datasets = {"dnsmasq.log": DNSMASQ}
    docs = _docs(datasets, offset=timedelta(days=400))
    monkeypatch.setattr(sw.Sweep, "_window_dataset_counts", lambda self, target, contract: (None, "count withheld"))
    snapshot, summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets, docs=docs)
    [row] = [row for row in rows if row["dataset"] == "dnsmasq.log"]
    assert row["records"] is None and row["count_scope"].startswith("not counted")
    assert any("dnsmasq.log (not counted)" in reason for reason in summary["partial_reasons"])
    assert _reconciliation_cells(snapshot)
    _assert_not_performed(summary, rows, "count withheld")


def _assert_not_performed(summary, rows, why):
    """The reconciliation itself is stated: one row and one partial reason naming the target and the cause."""
    stated = [row for row in rows if row["reason"].startswith(f"dataset reconciliation not performed on "
                                                                f"{tf.HOST_TARGET}: ")]
    assert len(stated) == 1 and why in stated[0]["reason"] and stated[0]["records"] is None
    assert stated[0]["dataset"] == "any dataset not read in full"
    assert [reason for reason in summary["partial_reasons"]
            if reason.startswith(f"{tf.HOST_TARGET}: dataset reconciliation not performed: ")] == [
        f"{tf.HOST_TARGET}: dataset reconciliation not performed: " + stated[0]["count_scope"].removeprefix(
            "not counted: ")]


def _failing_window_count(monkeypatch, outcome):
    """Make only the reconciliation's window aggregate fail (raise) or answer incompletely (an outcome)."""
    real = sw.execute

    def execute(client, intent, contract, *args, **kwargs):
        if intent.purpose == "sweep dataset reconciliation":
            if isinstance(outcome, Exception):
                raise outcome
            return outcome(real(client, intent, contract, *args, **kwargs))
        return real(client, intent, contract, *args, **kwargs)
    monkeypatch.setattr(sw, "execute", execute)


def test_reconciliation_not_performed_when_the_window_count_raises(tmp_path, monkeypatch):
    _failing_window_count(monkeypatch, RuntimeError("cluster gone"))
    datasets = {"dnsmasq.log": DNSMASQ}
    snapshot, summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets)
    assert snapshot["stats"]["records"] == 3       # retrieval itself was unaffected
    _assert_not_performed(summary, rows, "the window count by dataset failed (RuntimeError: cluster gone)")


def test_reconciliation_not_performed_when_the_window_count_is_partial(tmp_path, monkeypatch):
    from romulus.sources.models import Completeness

    _failing_window_count(monkeypatch, lambda out: out.model_copy(update={
        "completeness": Completeness.partial, "reasons": ["timed_out", "shard_failures"]}))
    _snapshot, summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, {"dnsmasq.log": DNSMASQ})
    _assert_not_performed(summary, rows, "not complete (timed_out; shard_failures)")


def test_reconciliation_not_performed_past_the_bucket_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "WINDOW_DATASET_BUCKETS", 1)
    datasets = {"dnsmasq.log": DNSMASQ, "horde.log": HORDE}
    _snapshot, summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets)
    _assert_not_performed(summary, rows, "aggregate_bucket_cap:1")


def test_reconciliation_not_performed_when_the_dataset_field_cannot_be_aggregated(tmp_path, monkeypatch):
    types = {**FILEBEAT_TYPES, "event.dataset": "keyword:no_doc_values"}
    datasets = {"dnsmasq.log": DNSMASQ}
    snapshot, summary, rows = _run(tmp_path, monkeypatch, types, datasets)
    assert snapshot["stats"]["records"] == 3       # still selected and read by the dataset predicate
    _assert_not_performed(summary, rows, "event.dataset is not aggregatable on this target (mapped as "
                                         "keyword:no_doc_values)")


def test_data_stream_dataset_without_doc_values_raises_no_spurious_no_dataset_row(tmp_path, monkeypatch):
    """data_stream.dataset is mapped but cannot be counted: the window inventory and the retrieval tally both place a
    record naming its dataset only there among the records naming none, so nothing is stated as missed."""
    types = {**FILEBEAT_TYPES, "data_stream.dataset": "keyword:no_doc_values"}
    datasets = {"dnsmasq.log": DNSMASQ}
    docs = _docs(datasets)
    builder_doc = dict(docs[tf.HOST_TARGET][0])
    source = {key: value for key, value in builder_doc["_source"].items() if key != "event"}
    source["data_stream"] = {"dataset": "stream.only"}
    docs[tf.HOST_TARGET].append({**builder_doc, "_id": "stream-only-1", "_source": source})
    snapshot, summary, rows = _run(tmp_path, monkeypatch, types, datasets, docs=docs)
    assert snapshot["stats"]["records"] == 4
    assert not [row for row in rows if row["dataset"] == "(records naming no dataset)"]
    assert not any("reconciliation not performed" in reason for reason in summary["partial_reasons"])


def test_real_filebeat_mapping_selects_text_through_message_only():
    from romulus.sources.compile import compile_es
    from romulus.sources.models import Predicate, SearchIntent, Window
    from romulus.sources.profile import flatten_mapping

    types = flatten_mapping(REAL_MAPPING)
    assert types["event.original"] == "keyword:not_indexed" and types["message"] == "match_only_text"
    contract = contract_from_types("logs", types)
    original = contract.spec("event.original")
    assert original.ops == [] and original.aggregatable is False
    assert contract.supports("message", "exists")
    query = compile_es(SearchIntent(kind="raw", target="logs", window=Window(start=tf.WINDOW_START,
                                                                                end=tf.WINDOW_END),
                                        filters=[Predicate(field="event.dataset", op="in", value=["linux.text"])]),
                           contract).body["query"]
    text = str(query)
    assert "{'exists': {'field': 'message'}}" in text and "event.original" not in text


@pytest.mark.parametrize("spec,kind", [
    ({"type": "keyword"}, "keyword"),
    ({"type": "keyword", "index": False, "doc_values": False}, "keyword:not_indexed"),
    ({"type": "keyword", "index": "false"}, "keyword:doc_values_only"),
    ({"type": "long", "doc_values": False}, "long:no_doc_values"),
    ({"type": "text", "index": False}, "text:not_indexed"),
    ({"type": "text"}, "text"),
])
def test_switched_off_index_or_doc_values_qualify_the_type(spec, kind):
    from romulus.sources.profile import AGGREGATABLE, mapped_kind

    assert mapped_kind(spec) == kind
    base = spec["type"]
    searchable = "index" not in spec
    assert bool(OPS_BY_TYPE.get(kind)) == (searchable and bool(OPS_BY_TYPE.get(base)))
    assert (kind in AGGREGATABLE) == (base in AGGREGATABLE and str(spec.get("doc_values", True)) != "False")


def test_tally_overflow_never_attributes_a_shortfall_it_cannot_count(tmp_path, monkeypatch):
    """Past the bounded name tally, a selected dataset with no tallied records is stated as not counted, never as
    complete and never with an invented count."""
    datasets = {f"app{n:02d}.log": APP for n in range(4)}
    docs = _docs(datasets)
    # the payload of one dataset is missing, so it is not retrieved; the tally keeps only two names
    for row in docs[tf.HOST_TARGET]:
        if row["_source"]["event"]["dataset"] == "app03.log":
            row["_source"].pop("message")
    monkeypatch.setattr(sw, "RETRIEVED_DATASET_NAMES", 2)
    _snapshot, summary, rows = _run(tmp_path, monkeypatch, FILEBEAT_TYPES, datasets, docs=docs)
    stated = {row["dataset"]: row for row in rows if row["dataset"] in datasets}
    assert "app03.log" in stated and stated["app03.log"]["records"] is None
    assert all(row["records"] is None for row in stated.values())
    assert any("were not retrieved" in reason for reason in summary["partial_reasons"])


def test_retrieval_tally_is_bounded_at_mission_scale():
    """A quarter of a million records over thousands of dataset names: the tally keeps a bounded number of names and
    counts every record exactly once."""
    sweep = sw.Sweep.__new__(sw.Sweep)
    contract = contract_from_types("logs", FILEBEAT_TYPES)
    records = [{"_source": {"event": {"dataset": f"ds{n % 5000}"}}} for n in range(250_000)]
    records += [{"_source": {"message": "no dataset"}}] * 10
    for start in range(0, len(records), 50_000):
        sweep._tally_retrieved("logs", contract, records[start:start + 50_000])
    tally = sweep._retrieved_datasets["logs"]
    assert len(tally) <= sw.RETRIEVED_DATASET_NAMES + 1
    assert sum(tally.values()) == len(records)
    assert tally[sw._TALLY_OVERFLOW] > 0


@pytest.mark.parametrize("source,expected", [
    ({"event": {"dataset": "a"}, "data_stream": {"dataset": "b"}}, "a"),
    ({"event": {"dataset": ""}, "data_stream": {"dataset": "b"}}, "b"),
    ({"event.dataset": "flat"}, "flat"),
    ({"message": "x"}, None),
])
def test_dataset_name_follows_the_window_inventory_precedence(source, expected):
    assert sw._dataset_name(source, "event.dataset", "data_stream.dataset") == expected
