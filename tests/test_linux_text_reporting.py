"""Synthetic profile and report checks for bounded text-log inventory and honest gaps."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from romulus import doctor
from romulus.evidence.linux_catalog import LOGICAL_FAMILIES
from romulus.hunt.sweep import delivered_families
from romulus.report.manifest import _not_assessed
from romulus.sources.profile import build_profile


def _mapping(fields):
    properties = {}
    for name, kind in fields.items():
        cursor = properties
        parts = name.split(".")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {"properties": {}})["properties"]
        cursor[parts[-1]] = {"type": kind}
    return {"logs": {"mappings": {"properties": properties}}}


FIELDS = {"@timestamp": "date", "event.dataset": "keyword", "host.name": "keyword", "message": "text"}
SYSLOG = "Nov 09 10:20:30 mail dovecot: imap-login: Login: user=<alice>, method=PLAIN, rip=192.0.2.1"


class ProfileClient:
    version = "8.15.0"
    settings = SimpleNamespace(es_flavor="elasticsearch")

    def __init__(self, inventory, samples=(), fields=None, *, records=None, secondary=()):
        self.inventory, self.samples = inventory, list(samples)
        self.records = sum(inventory.values()) if records is None else records
        self.secondary = list(secondary)
        self.fields = dict(FIELDS if fields is None else fields)
        self.bodies = []

    def mapping(self, _target):
        return _mapping(self.fields)

    def resolve(self, _pattern):
        return ["logs"]

    def search(self, _target, body):
        self.bodies.append(body)
        if "aggs" in body:
            if "query" in body:
                assert body["size"] == 0
                assert self.secondary, "unexpected secondary inventory query"
                response = self.secondary.pop(0)
                if isinstance(response, Exception):
                    raise response
                return response
            return {"hits": {"total": {"value": self.records, "relation": "eq"}},
                    "aggregations": {"ds": {"buckets": [{"key": name, "doc_count": count}
                                                          for name, count in self.inventory.items()]},
                                     "hosts": {"buckets": []}}}
        assert body["size"] <= 1000
        assert self.samples, "unexpected sample query"
        response = self.samples.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _sample(messages, dataset="custom.mail", total=None, **extra):
    hits = [{"_source": {"event": {"dataset": dataset}, "message": message}} for message in messages]
    return {"hits": {"total": {"value": len(hits) if total is None else total, "relation": "eq"},
                     "hits": hits}, **extra}


def test_actual_inventory_and_nonadditive_rollup_feed_existing_family_contract():
    client = ProfileClient({"custom.mail": 20, "myapp": 7},
                           [_sample([SYSLOG, "not a recognized line"]), _sample(["debug text"], "myapp")])
    profile, contract = build_profile(client, "logs")
    assert profile.datasets == {"custom.mail": 20, "myapp": 7, "linux.text": 27}
    detail = profile.model_dump()["linux_text"]
    assert detail["inventory"] == {"custom.mail": 20, "myapp": 7}
    assert detail["rollup"]["records"] == 27
    assert detail["rollup"]["non_additive"] is True
    assert "potential source records" in detail["count_scope"]
    assert profile.doc_count == 27
    assert LOGICAL_FAMILIES["linux.text"] <= delivered_families(profile.model_dump(), contract)
    sample = detail["samples"]["custom.mail"]
    assert sample["sampled"] == 2
    assert sample["formats"] == {"syslog": 1, "unknown": 1}
    assert sample["programs"] == {"dovecot": 1}
    assert sample["complete"] is False
    assert client.bodies[1]["query"] == {"term": {"event.dataset": "custom.mail"}}


def test_sample_limit_and_unknown_program_are_visible_without_typing_claims():
    lines = ["Nov 09 10:20:30 host custom-app: debug"] * 1000
    client = ProfileClient({"custom.debug": 1001}, [_sample(lines, "custom.debug")])
    profile, _ = build_profile(client, "logs")
    sample = profile.model_dump()["linux_text"]["samples"]["custom.debug"]
    assert sample["sampled"] == 1000
    assert sample["programs"] == {"custom-app": 1000}
    assert sample["formats"] == {"syslog": 1000}
    assert sample["complete"] is False
    assert any("1000" in note for note in sample["notes"])


@pytest.mark.parametrize("partial", [{"timed_out": True}, {"_shards": {"failed": 1}}])
def test_incomplete_source_sample_never_claims_complete_inventory_read(partial):
    profile, _ = build_profile(ProfileClient({"myapp": 1}, [_sample([SYSLOG], "myapp", **partial)]), "logs")
    sample = profile.model_dump()["linux_text"]["samples"]["myapp"]
    assert sample["complete"] is False
    assert sample["notes"]


def test_datasetless_file_input_is_counted_by_the_source_not_by_sample_size():
    fields = {"@timestamp": "date", "message": "text", "input.type": "keyword", "host.name": "keyword"}
    client = ProfileClient({}, [_sample([SYSLOG], "", total=14)], fields)
    profile, contract = build_profile(client, "logs")
    assert profile.datasets == {"linux.text": 14}
    detail = profile.model_dump()["linux_text"]
    assert detail["inventory"] == {}
    assert detail["datasetless"]["records"] == 14
    assert detail["datasetless"]["sampled"] == 1
    assert LOGICAL_FAMILIES["linux.text"] <= delivered_families(profile.model_dump(), contract)
    assert client.bodies[1]["track_total_hits"] is True
    assert "filestream" in json.dumps(client.bodies[1]["query"])


def test_uncounted_datasetless_sources_use_unknown_and_conservative_coverage():
    fields = {"@timestamp": "date", "message": "text", "log.file.path": "keyword"}
    response = _sample([SYSLOG], "", total=10000)
    response["hits"]["total"]["relation"] = "gte"
    profile, contract = build_profile(ProfileClient({}, [response], fields), "logs")
    detail = profile.model_dump()["linux_text"]
    assert detail["rollup"]["records"] is None
    assert "linux.text" not in profile.datasets
    assert any(note.startswith("ds inventory truncated") for note in profile.notes)
    assert delivered_families(profile.model_dump(), contract)


@pytest.mark.parametrize("inventory,extra", [
    ({"system.auth": 7}, {}),
    ({"custom.windows": 7}, {"winlog.event_id": "keyword", "winlog.channel": "keyword"}),
    ({"zeek.conn": 7}, {"source.ip": "ip", "destination.ip": "ip"}),
])
def test_existing_profile_shape_and_hash_material_have_no_new_empty_fields(inventory, extra):
    # The Windows mapping's message field needs the new bounded non-Windows-text source check. Zero keeps the
    # original profile material unchanged; this fixture is intentionally a pure Windows source.
    samples = [{"hits": {"total": {"value": count, "relation": "eq"}, "hits": []}} for count in (7, 0)] \
        if "winlog.channel" in extra else []
    profile, _ = build_profile(ProfileClient(inventory, samples=samples, fields={**FIELDS, **extra}), "logs")
    assert profile.datasets == inventory
    assert "linux_text" not in profile.model_dump()
    assert profile.notes == []


def test_report_lists_actual_gap_datasets_and_summary_without_double_counting():
    unknown_a = "text line in no recognized format: custom.mail"
    unknown_b = "text line in no recognized format: app.debug"
    untyped = "text format syslog, program unhandled is not normalized: custom.mail"
    rows = _not_assessed({}, {"stats": {
        "skips_by_target": {"logs": {unknown_a: 4, unknown_b: 2, untyped: 3}},
        "skips": {unknown_a: 4, unknown_b: 2, untyped: 3},
    }})
    assert sum(row["records"] or 0 for row in rows) == 9
    assert {(row["dataset"], row["records"]) for row in rows if row["records"]} == {
        ("custom.mail", 4), ("app.debug", 2), ("custom.mail", 3)}
    assert any("6 lines in 2 datasets in no recognized format" in row["reason"] for row in rows)
    assert any("program unhandled" in row["reason"] for row in rows)


def test_report_does_not_list_nonadditive_rollup_as_an_unswept_actual_dataset():
    profile = {"datasets": {"custom.mail": 20, "linux.text": 20},
               "linux_text": {"inventory": {"custom.mail": 20}, "rollup": {"non_additive": True}}}
    rows = _not_assessed({"source_profiles": {"logs": profile}},
                         {"stats": {"dataset_filter": {"logs": ["custom.mail"]}}})
    assert rows == []


def test_old_report_shape_stays_identical_without_new_text_skip_reasons():
    reason = "unhandled legacy record"
    rows = _not_assessed({}, {"stats": {"skips": {reason: 2}}})
    assert rows == [{"target": "all sweep targets", "dataset": None, "records": 2,
                     "count_scope": "records retrieved in the hunt window",
                     "reason": "retrieved but not turned into a typed event: " + reason}]


def test_doctor_displays_actual_names_potential_counts_and_bounded_sample():
    check = getattr(doctor, "check_linux_text_sources", None)
    assert callable(check)
    client = ProfileClient({"custom.mail": 20}, [_sample([SYSLOG])])
    settings = SimpleNamespace(es_index_patterns=["logs*"], home=None)
    result = check(settings, client=client)
    assert len(result) == 1
    assert result[0].status == "warn"
    assert all(part in result[0].detail for part in ("custom.mail", "20 potential source records", "sampled 1",
                                                    "syslog=1", "dovecot=1"))
    assert result[0].data["rollup"]["non_additive"] is True


def test_doctor_has_no_new_output_for_legacy_profiles():
    check = getattr(doctor, "check_linux_text_sources", None)
    assert callable(check)
    assert check(SimpleNamespace(es_index_patterns=["logs*"], home=None),
                 client=ProfileClient({"system.auth": 4})) == []


def test_sample_error_preserves_actual_count_and_marks_format_mix_unknown():
    from romulus.errors import SourceError

    profile, contract = build_profile(ProfileClient({"custom.mail": 27}, [SourceError("sample refused")]), "logs")
    assert profile.datasets["custom.mail"] == 27
    assert profile.datasets["linux.text"] == 27
    sample = profile.model_dump()["linux_text"]["samples"]["custom.mail"]
    assert sample["sampled"] == 0 and sample["complete"] is False
    assert sample["formats"] == {} and "unavailable" in sample["notes"][0]
    assert LOGICAL_FAMILIES["linux.text"] <= delivered_families(profile.model_dump(), contract)


def test_early_termination_does_not_fabricate_exact_datasetless_count():
    fields = {"@timestamp": "date", "message": "text", "input.type": "keyword"}
    profile, _ = build_profile(ProfileClient({}, [_sample([SYSLOG], "", total=3, terminated_early=True)], fields),
                               "logs")
    assert profile.model_dump()["linux_text"]["rollup"]["records"] is None
    assert "linux.text" not in profile.datasets


def test_mapped_dataset_field_does_not_hide_datasetless_file_records():
    fields = {**FIELDS, "input.type": "keyword", "log.file.path": "keyword", "event.module": "keyword"}
    client = ProfileClient({"system.auth": 7}, [_sample([SYSLOG], "", total=2)], fields, records=9)
    profile, contract = build_profile(client, "logs")
    assert profile.doc_count == 9
    assert profile.datasets == {"system.auth": 7, "linux.text": 2}
    detail = profile.model_dump()["linux_text"]
    assert detail["datasetless"]["records"] == 2
    assert detail["datasetless"]["sampled"] == 1
    assert LOGICAL_FAMILIES["linux.text"] <= delivered_families(profile.model_dump(), contract)
    query = client.bodies[1]["query"]["bool"]
    assert {"bool": {"should": [
        {"bool": {"must_not": [{"exists": {"field": "event.dataset"}}]}},
        {"term": {"event.dataset": ""}},
    ], "minimum_should_match": 1}} in query["filter"]
    assert {"bool": {"must_not": [{"exists": {"field": "data_stream.dataset"}}]}} in query["filter"]
    assert {"bool": {"should": [{"exists": {"field": "message"}}], "minimum_should_match": 1}} in query["filter"]
    assert {"bool": {"should": [
        {"terms": {"input.type": ["filestream", "log", "syslog", "tcp", "udp"]}},
        {"exists": {"field": "log.file.path"}},
    ], "minimum_should_match": 1}} in query["filter"]
    assert query["must_not"] == [{"terms": {"event.module": ["auditd", "system", "apache"]}}]


def test_zero_datasetless_count_keeps_legacy_profile_hash_and_shape():
    fields = {**FIELDS, "input.type": "keyword"}
    client = ProfileClient({"system.auth": 7}, [_sample([], "", total=0)], fields)
    profile, _ = build_profile(client, "logs")
    assert len(client.bodies) == 2
    assert not client.samples
    assert profile.datasets == {"system.auth": 7}
    assert "linux_text" not in profile.model_dump()
    assert profile.notes == []
    # Recorded from the pre-fix profile with exactly these fields and source counts.
    assert profile.id == "b22f7a2a7cbd375a"


def test_zero_datasetless_count_adds_no_empty_sample_to_existing_text_inventory():
    client = ProfileClient({"myapp": 1}, [_sample([SYSLOG], "myapp"), _sample([], "", total=0)],
                           {**FIELDS, "input.type": "keyword"})
    profile, _ = build_profile(client, "logs")
    detail = profile.model_dump()["linux_text"]
    assert "datasetless" not in detail
    assert detail["rollup"]["includes_datasetless"] is False


def _secondary_inventory(counts, **extra):
    return {"hits": {"total": {"value": sum(counts.values()), "relation": "eq"}},
            "aggregations": {"ds": {"buckets": [{"key": name, "doc_count": count}
                                                  for name, count in counts.items()]}}, **extra}


def test_secondary_dataset_inventory_uses_record_precedence_and_merges_actual_names():
    fields = {**FIELDS, "data_stream.dataset": "keyword", "input.type": "keyword"}
    client = ProfileClient({"myapp": 3}, [_sample([SYSLOG], "myapp"), _sample([], "", total=0)],
                           fields, records=8, secondary=[_secondary_inventory({"myapp": 5})])
    profile, _ = build_profile(client, "logs")
    assert profile.doc_count == 8
    assert profile.datasets == {"myapp": 8, "linux.text": 8}
    assert profile.model_dump()["linux_text"]["inventory"] == {"myapp": 8}
    fallback = client.bodies[1]
    assert fallback["size"] == 0
    assert fallback["aggs"] == {"ds": {"terms": {"field": "data_stream.dataset", "size": 200}}}
    missing_primary = {"bool": {"should": [
        {"bool": {"must_not": [{"exists": {"field": "event.dataset"}}]}},
        {"term": {"event.dataset": ""}},
    ], "minimum_should_match": 1}}
    assert missing_primary in fallback["query"]["bool"]["filter"]
    assert client.bodies[2]["query"] == {"bool": {"should": [
        {"term": {"event.dataset": "myapp"}},
        {"bool": {"filter": [missing_primary, {"term": {"data_stream.dataset": "myapp"}}]}},
    ], "minimum_should_match": 1}}
    missing_secondary = {"bool": {"should": [
        {"bool": {"must_not": [{"exists": {"field": "data_stream.dataset"}}]}},
        {"term": {"data_stream.dataset": ""}},
    ], "minimum_should_match": 1}}
    assert missing_primary in client.bodies[3]["query"]["bool"]["filter"]
    assert missing_secondary in client.bodies[3]["query"]["bool"]["filter"]


def test_empty_primary_dataset_is_not_double_counted_as_a_named_source():
    fields = {**FIELDS, "data_stream.dataset": "keyword", "input.type": "keyword"}
    client = ProfileClient({"": 5}, [_sample([SYSLOG], "myapp"), _sample([], "", total=0)],
                           fields, secondary=[_secondary_inventory({"myapp": 5})])
    profile, _ = build_profile(client, "logs")
    assert profile.datasets == {"myapp": 5, "linux.text": 5}
    assert profile.model_dump()["linux_text"]["inventory"] == {"myapp": 5}


@pytest.mark.parametrize("secondary", [
    {"timed_out": True, "aggregations": {"ds": {"buckets": []}}},
    {"aggregations": {"ds": {"buckets": [], "sum_other_doc_count": 5}}},
    {},
])
def test_incomplete_secondary_inventory_keeps_coverage_conservative(secondary):
    fields = {**FIELDS, "data_stream.dataset": "keyword"}
    profile, contract = build_profile(ProfileClient({}, fields=fields, records=2, secondary=[secondary]), "logs")
    assert any(note.startswith("ds inventory truncated") and "data_stream.dataset" in note
               for note in profile.notes)
    assert delivered_families(profile.model_dump(), contract)


def test_secondary_inventory_source_error_is_an_explicit_gap():
    from romulus.errors import SourceError

    fields = {**FIELDS, "data_stream.dataset": "keyword"}
    profile, contract = build_profile(ProfileClient({}, fields=fields, records=2,
                                     secondary=[SourceError("fallback refused")]), "logs")
    assert any("fallback refused" in note for note in profile.notes)
    assert delivered_families(profile.model_dump(), contract)


def test_doctor_names_datasetless_values_in_mapped_indexes():
    checks = doctor.check_linux_text_sources(SimpleNamespace(es_index_patterns=["logs*"], home=None),
        client=ProfileClient({}, [_sample([SYSLOG], "", total=2)], {**FIELDS, "input.type": "keyword"}, records=2))
    assert len(checks) == 1
    assert "no dataset value: 2 potential source records" in checks[0].detail
    assert "dovecot=1" in checks[0].detail


def test_doctor_warns_when_secondary_inventory_cannot_establish_absence():
    from romulus.errors import SourceError

    checks = doctor.check_linux_text_sources(SimpleNamespace(es_index_patterns=["logs*"], home=None),
        client=ProfileClient({}, fields={**FIELDS, "data_stream.dataset": "keyword"}, records=2,
                             secondary=[SourceError("fallback refused")]))
    assert len(checks) == 1
    assert checks[0].status == "warn"
    assert "data_stream.dataset" in checks[0].detail and "fallback refused" in checks[0].detail


def test_zero_secondary_and_datasetless_counts_keep_legacy_profile_unchanged():
    fields = {**FIELDS, "data_stream.dataset": "keyword", "input.type": "keyword"}
    client = ProfileClient({"system.auth": 7}, [_sample([], "", total=0)], fields,
                           secondary=[_secondary_inventory({})])
    profile, _ = build_profile(client, "logs")
    assert len(client.bodies) == 3 and not client.samples and not client.secondary
    assert profile.datasets == {"system.auth": 7}
    assert profile.notes == []
    assert "linux_text" not in profile.model_dump()
    assert profile.id == "7b8ebb97e52391ec"


def test_doctor_warns_on_unrecognized_lines_even_when_whole_sample_was_read():
    checks = doctor.check_linux_text_sources(SimpleNamespace(es_index_patterns=["logs*"], home=None),
        client=ProfileClient({"myapp": 1}, [_sample(["unknown line"], "myapp")]))
    assert checks[0].status == "warn"
    assert "unknown=1" in checks[0].detail


def test_profile_and_hunt_manifest_preserve_optional_text_metadata():
    from datetime import UTC, datetime, timedelta

    from romulus.config import Settings
    from romulus.hunt.manifest import build_manifest
    from romulus.sources.models import Window

    profile, _ = build_profile(ProfileClient({"myapp": 1}, [_sample([SYSLOG], "myapp")]), "logs")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    manifest = build_manifest(Settings(), Window(start=now, end=now + timedelta(hours=1)), {}, "broad",
                              ["logs"], {"logs": profile.model_dump(mode="json")})
    assert manifest["source_profiles"]["logs"]["linux_text"] == profile.model_dump()["linux_text"]
    old, _ = build_profile(ProfileClient({"system.auth": 1}), "logs")
    legacy = build_manifest(Settings(), Window(start=now, end=now + timedelta(hours=1)), {}, "broad",
                            ["logs"], {"logs": old.model_dump(mode="json")})
    assert "linux_text" not in legacy["source_profiles"]["logs"]


def test_report_counts_scoped_and_unscoped_remainder_once():
    reason = "text line in no recognized format: myapp"
    rows = _not_assessed({}, {"stats": {"skips_by_target": {"a": {reason: 2}},
                                       "skips_scoped_global": {reason: 2}, "skips": {reason: 5}}})
    assert sum(row["records"] or 0 for row in rows) == 5
    assert any("5 lines in 1 datasets" in row["reason"] for row in rows)


def test_rendered_not_assessed_section_names_formats_and_datasets():
    from romulus.report.manifest import publish_revision
    from romulus.report.markdown import render
    from tests.test_report import _repo_with_finding

    repo, _ = _repo_with_finding()
    try:
        manifest = publish_revision(repo, "h1", "test")
        manifest["coverage"]["not_assessed"] = _not_assessed({}, {"stats": {"skips": {
            "text line in no recognized format: myapp": 3,
            "text format application, program smb-unknown is not normalized: auth.custom": 2,
        }}})
        section = render(manifest).split("### Data not assessed", 1)[1]
        assert "3 lines in 1 datasets in no recognized format" in section
        assert "myapp" in section and "auth.custom" in section and "smb-unknown" in section
    finally:
        repo.engine.dispose()
