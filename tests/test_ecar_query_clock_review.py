"""Only chronologically searchable eCAR mappings may supply the query clock."""
from copy import deepcopy
from datetime import timedelta

import pytest

from romulus.errors import SourceError
from romulus.sources.compile import compile_es
from romulus.sources.models import SearchIntent
from romulus.sources.profile import build_profile, contract_from_types
from tests.test_host_shapes_profile import WINDOW, mapping
from tests.test_host_shapes_profile_ecar import EcarClockProfileClient, _ecar_clock_rows, ecar_types


@pytest.mark.parametrize("field", ["timestamp_ms", "timestamp"])
@pytest.mark.parametrize("kind", ["date", "date_nanos", "long", "integer", "double", "float"])
def test_supported_native_clock_mapping_stays_native(field, kind):
    contract = contract_from_types("raw", {**ecar_types(field), field: kind, "@timestamp": "date"})
    assert contract.time_field == field and not contract.temporal_gaps
    query = compile_es(SearchIntent(kind="raw", target="raw", window=WINDOW), contract)
    assert next(iter(query.body["query"]["bool"]["filter"][0]["range"])) == field


@pytest.mark.parametrize("field", ["timestamp_ms", "timestamp"])
@pytest.mark.parametrize("kind", ["keyword", "text", "wildcard", "mixed", "boolean", "object"])
def test_unsupported_native_clock_mapping_uses_pipeline_with_temporal_gap(field, kind):
    contract = contract_from_types("raw", {**ecar_types(field), field: kind, "@timestamp": "date"})
    assert contract.time_field == "@timestamp"
    assert any(field in gap and kind in gap and "native-clock window membership unresolved" in gap
               for gap in contract.temporal_gaps)


class StrictClockClient(EcarClockProfileClient):
    def search(self, target, body):
        clock = body.get("aggs", {}).get("tmin", {}).get("min", {}).get("field")
        if clock and self.fields.get(clock) not in {"date", "date_nanos", "long", "integer", "double", "float"}:
            raise SourceError("400: min/max cannot aggregate this clock mapping")
        return super().search(target, body)


def test_keyword_iso_timestamp_profile_starts_and_real_link_is_honestly_partial(tmp_path):
    from romulus.config import Settings
    from romulus.evidence.ecar import normalize_ecar
    from romulus.hunt.links import LinkAnchor, LinkFetcher, LinkWindow
    from romulus.hunt.pivot import PivotExecutor
    from romulus.sources.es import ElasticClient
    from tests.test_sweep import _repo
    from tests.throughput_fixture import MiniES

    rows = _ecar_clock_rows("timestamp", "date")
    rows[1]["_source"]["timestamp"] = "2025-01-01T02:00:01+01:00"
    fields = {**ecar_types("timestamp"), "timestamp": "keyword", "@timestamp": "date"}
    profile, contract = build_profile(StrictClockClient(fields, rows), "raw")
    assert contract.time_field == "@timestamp"
    assert any("native-clock window membership unresolved" in note for note in profile.notes)
    client = ElasticClient(Settings(es_url="http://es.invalid"),
        transport=MiniES({"raw": rows}, {"raw": contract.time_field}).transport())
    repo = _repo()
    root, later = [normalize_ecar(row) for row in rows]
    anchor = LinkAnchor(finding_id="clock", ts=root.ts, host=root.host, event_ids=[root.id], events=[root])
    try:
        executor = PivotExecutor(repo, client, "h1", {"raw": contract}, stage_dir=tmp_path)
        result = LinkFetcher(executor, WINDOW.start, WINDOW.end).fetch(anchor, "host_after_anchor",
            LinkWindow(label="native time", start=root.ts, end=root.ts + timedelta(minutes=5)))
        assert result.status == "partial" and later.id not in result.event_ids
        assert any("native-clock window membership unresolved" in note for note in result.reasons)
    finally:
        repo.engine.dispose()


def test_timestamp_missing_on_one_pattern_index_remains_counted_as_omitted():
    rows = _ecar_clock_rows("timestamp", "date")
    rows[1]["_source"].pop("timestamp")
    fields = {**ecar_types("timestamp"), "timestamp": "date", "@timestamp": "date"}

    class PatternClient(StrictClockClient):
        def mapping(self, target):
            result = mapping(self.fields)
            second = deepcopy(result["raw"])
            second["mappings"]["properties"].pop("timestamp")
            result["raw-second"] = second
            return result

    profile, contract = build_profile(PatternClient(fields, rows), "raw*")
    assert contract.time_field == "timestamp"
    [gap] = profile.model_dump()["temporal_gaps"]
    assert gap["records"] == 1 and gap["alternate"] == "@timestamp"
    assert contract.temporal_gaps == (gap["reason"],)
