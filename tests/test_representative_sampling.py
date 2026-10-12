import copy
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from romulus.config import Settings
from romulus.tools.arkime_client import ArkimeAdapter
from romulus.tools.elasticsearch_client import ElasticsearchAdapter


class _Indices:
    def get(self, **kwargs):
        return {"synthetic-host": {}}


def _range_clauses(value):
    clauses = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "range" and isinstance(child, dict):
                clauses.extend((field, bounds) for field, bounds in child.items())
            else:
                clauses.extend(_range_clauses(child))
    elif isinstance(value, list):
        for child in value:
            clauses.extend(_range_clauses(child))
    return clauses


class _SyntheticElasticsearch:
    indices = _Indices()

    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)
        self.calls = []

    def open_point_in_time(self, **kwargs):
        return {"id": "synthetic-pit"}

    def close_point_in_time(self, **kwargs):
        return {"succeeded": True}

    def search(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        rows = list(self.rows)
        for field, bounds in _range_clauses(kwargs.get("query", {})):
            if field != "@timestamp":
                continue
            lower = bounds.get("gte", bounds.get("gt"))
            upper = bounds.get("lte", bounds.get("lt"))
            lower_inclusive = "gte" in bounds
            upper_inclusive = "lte" in bounds
            if lower is not None:
                rows = [row for row in rows if row["_source"][field] >= lower] if lower_inclusive else [
                    row for row in rows if row["_source"][field] > lower
                ]
            if upper is not None:
                rows = [row for row in rows if row["_source"][field] <= upper] if upper_inclusive else [
                    row for row in rows if row["_source"][field] < upper
                ]
        sort_items = kwargs.get("sort", [])
        timestamp_sort = next((item["@timestamp"] for item in sort_items if isinstance(item, dict) and "@timestamp" in item), {})
        reverse = timestamp_sort.get("order") == "desc"
        rows.sort(key=lambda row: (row["_source"]["@timestamp"], row["_id"]), reverse=reverse)
        search_after = kwargs.get("search_after")
        if search_after:
            marker = tuple(search_after)
            if reverse:
                rows = [row for row in rows if (row["_source"]["@timestamp"], row["_id"]) < marker]
            else:
                rows = [row for row in rows if (row["_source"]["@timestamp"], row["_id"]) > marker]
        total = len(rows)
        hits = []
        for row in rows[: kwargs.get("size", 10)]:
            item = copy.deepcopy(row)
            item["sort"] = [item["_source"]["@timestamp"], item["_id"]]
            hits.append(item)
        return {
            "hits": {"hits": hits, "total": {"value": total, "relation": "eq"}},
            "timed_out": False,
            "_shards": {"failed": 0},
        }


def _rows(count=16):
    start = datetime(2026, 2, 1, tzinfo=timezone.utc)
    return [
        {
            "_index": "synthetic-host",
            "_id": f"event-{index:02d}",
            "_source": {
                "@timestamp": (start + timedelta(minutes=30 * index)).isoformat().replace("+00:00", "Z"),
                "message": f"synthetic observation {index}",
            },
        }
        for index in range(count)
    ]


class ElasticsearchRepresentativeSamplingTests(unittest.TestCase):
    def _adapter(self, rows):
        settings = replace(
            Settings.from_env(),
            es_index_patterns=("synthetic-*",),
            max_results=20,
            time_sampling_strata=4,
        )
        return ElasticsearchAdapter(settings, _SyntheticElasticsearch(rows))

    def test_capped_search_retains_records_across_the_full_explicit_window(self):
        adapter = self._adapter(_rows())
        query = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "2026-02-01T00:00:00Z", "lte": "2026-02-01T08:00:00Z"}}}
                ]
            }
        }

        result = adapter.search_many(
            ["synthetic-host"],
            query,
            4,
            timestamp_field="@timestamp",
            time_range={"gte": "2026-02-01T00:00:00Z", "lte": "2026-02-01T08:00:00Z"},
            sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        )

        timestamps = [hit["@timestamp"] for hit in result["hits"]]
        self.assertEqual(len(timestamps), 4)
        self.assertEqual(timestamps[0], "2026-02-01T00:00:00Z")
        self.assertGreaterEqual(timestamps[-1], "2026-02-01T06:00:00Z")
        self.assertEqual(result["total"], 16)
        self.assertTrue(result["capped"])
        self.assertEqual(result["sampling"]["strategy"], "time_stratified")
        self.assertEqual(result["sampling"]["covered_strata"], 4)
        self.assertEqual(result["sampling"]["retained_by_stratum"], [1, 1, 1, 1])

    def test_capped_search_without_explicit_bounds_discovers_matching_extent(self):
        adapter = self._adapter(_rows())

        result = adapter.search_many(
            ["synthetic-host"],
            {"match": {"message": "synthetic"}},
            4,
            timestamp_field="@timestamp",
            sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        )

        timestamps = [hit["@timestamp"] for hit in result["hits"]]
        self.assertEqual(len(timestamps), 4)
        self.assertGreaterEqual(timestamps[-1], "2026-02-01T05:30:00Z")
        self.assertEqual(result["sampling"]["bounds_source"], "matching_extrema")

    def test_capped_search_does_not_retain_the_same_document_twice(self):
        rows = _rows(8)
        rows[6]["_id"] = rows[0]["_id"]
        adapter = self._adapter(rows)

        result = adapter.search_many(
            ["synthetic-host"],
            {"match": {"message": "synthetic"}},
            4,
            timestamp_field="@timestamp",
            time_range={"gte": "2026-02-01T00:00:00Z", "lte": "2026-02-01T04:00:00Z"},
            sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        )

        retained_ids = [hit["_id"] for hit in result["hits"]]
        self.assertEqual(len(retained_ids), len(set(retained_ids)))

    def test_uncapped_search_preserves_all_records_and_is_deterministic(self):
        rows = _rows(3)
        adapter = self._adapter(rows)
        kwargs = {
            "timestamp_field": "@timestamp",
            "time_range": {"gte": "2026-02-01T00:00:00Z", "lte": "2026-02-01T08:00:00Z"},
            "sampling": {"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        }

        first = adapter.search_many(["synthetic-host"], {"match": {"message": "synthetic"}}, 5, **kwargs)
        second = adapter.search_many(["synthetic-host"], {"match": {"message": "synthetic"}}, 5, **kwargs)

        self.assertEqual(first["hits"], second["hits"])
        self.assertEqual(len(first["hits"]), 3)
        self.assertFalse(first["capped"])
        self.assertEqual(first["sampling"]["strategy"], "exhaustive")


class _SyntheticArkime(ArkimeAdapter):
    def __init__(self, settings, rows=None, total=None):
        self.settings = settings
        self.rows = copy.deepcopy(rows) if rows is not None else None
        self.total = len(rows) if total is None and rows is not None else int(total or 0)
        self.calls = []

    def search_sessions(self, expression, **kwargs):
        start = int(kwargs.get("start", 0))
        length = int(kwargs.get("length", 100))
        self.calls.append({"expression": expression, "start": start, "length": length})
        if self.rows is None:
            rows = [{"id": f"session-{index:08d}", "firstPacket": index} for index in range(start, min(start + length, self.total))]
        else:
            rows = copy.deepcopy(self.rows[start : start + length])
        return {"sessions": rows, "total": self.total, "provenance": {"expression": expression}}


class ArkimeRepresentativeSamplingTests(unittest.TestCase):
    def _adapter(self, rows=None, total=None):
        settings = replace(Settings.from_env(), arkime_max_results=100, time_sampling_strata=4)
        return _SyntheticArkime(settings, rows=rows, total=total)

    def test_capped_search_reads_stable_windows_across_the_ordered_result_set(self):
        adapter = self._adapter(total=100)

        result = adapter.search_sessions_sampled(
            "ip.protocol == tcp",
            limit=12,
            sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        )

        self.assertEqual([call["start"] for call in adapter.calls], [0, 0, 32, 65, 97])
        self.assertEqual(len(result["sessions"]), 12)
        self.assertEqual(result["total"], 100)
        self.assertTrue(result["capped"])
        self.assertEqual(result["sampling"]["strategy"], "rank_stratified")
        self.assertEqual(result["sampling"]["covered_strata"], 4)
        self.assertEqual(result["sampling"]["retained_by_stratum"], [3, 3, 3, 3])

    def test_rank_sampling_suppresses_duplicate_session_ids(self):
        rows = [{"id": f"session-{index:02d}", "firstPacket": index} for index in range(20)]
        rows[13]["id"] = rows[0]["id"]
        adapter = self._adapter(rows=rows)

        result = adapter.search_sessions_sampled(
            "ip.protocol == tcp",
            limit=8,
            sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        )

        retained = [row["id"] for row in result["sessions"]]
        self.assertEqual(len(retained), len(set(retained)))
        self.assertEqual(result["duplicates_suppressed"], 1)

    def test_offset_limit_is_disclosed_as_incomplete_sampling(self):
        adapter = self._adapter(total=20_000_000)

        result = adapter.search_sessions_sampled(
            "ip.protocol == tcp",
            limit=8,
            sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        )

        self.assertTrue(result["capped"])
        self.assertLess(result["sampling"]["covered_strata"], result["sampling"]["requested_strata"])
        self.assertEqual(result["sampling"]["fallback_reason"], "arkime_offset_limit")
        self.assertTrue(all(call["start"] <= 10_000_000 for call in adapter.calls))

    def test_uncapped_search_returns_every_session_in_order(self):
        rows = [{"id": f"session-{index:02d}", "firstPacket": index} for index in range(3)]
        adapter = self._adapter(rows=rows)

        result = adapter.search_sessions_sampled(
            "ip.protocol == tcp",
            limit=5,
            sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        )

        self.assertEqual(result["sessions"], rows)
        self.assertFalse(result["capped"])
        self.assertEqual(result["sampling"]["strategy"], "exhaustive")


if __name__ == "__main__":
    unittest.main()
