import copy
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from romulus.config import Settings
from romulus.tools.arkime_client import ArkimeAdapter
from romulus.tools.elasticsearch_client import ElasticsearchAdapter
from romulus.tools.tshark_client import TSharkAdapter


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
        self.assertEqual(len(retained_ids), 4)
        self.assertEqual(len(retained_ids), len(set(retained_ids)))

    def test_failed_stratum_keeps_other_representative_rows_and_is_disclosed(self):
        client = _SyntheticElasticsearch(_rows())
        original_search = client.search

        def fail_one_stratum(**kwargs):
            ranges = _range_clauses(kwargs.get("query", {}))
            if any(bounds.get("gte") == "2026-02-01T02:00:00Z" for _, bounds in ranges):
                raise RuntimeError("synthetic stratum failure")
            return original_search(**kwargs)

        client.search = fail_one_stratum
        settings = replace(Settings.from_env(), es_index_patterns=("synthetic-*",), max_results=20,
            time_sampling_strata=4)
        adapter = ElasticsearchAdapter(settings, client)

        result = adapter.search_many(
            ["synthetic-host"], {"match": {"message": "synthetic"}}, 4,
            timestamp_field="@timestamp",
            time_range={"gte": "2026-02-01T00:00:00Z", "lte": "2026-02-01T08:00:00Z"},
            sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
        )

        self.assertEqual(result["sampling"]["strategy"], "time_stratified")
        self.assertEqual(result["sampling"]["covered_strata"], 3)
        self.assertEqual(result["sampling"]["failed_strata"], 1)
        self.assertEqual(result["sampling"]["fallback_reason"], "stratum_error")
        self.assertEqual(result["sampling"]["retained_by_stratum"], [1, 0, 1, 1])
        self.assertEqual(len(result["hits"]), 3)

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
        self.assertEqual(result["sampling"]["matched_by_stratum"], [3, 3, 3, 3])

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
        self.assertEqual(len(retained), 8)
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


class _SyntheticTSharkProcess:
    def __init__(self, lines):
        self.stdout = list(lines)
        self.stderr = []

    def wait(self, timeout=None):
        return 0

    def kill(self):
        return None


class TSharkRepresentativeSamplingTests(unittest.TestCase):
    def _inspect(self, lines, *, limit=4, malformed=False):
        settings = replace(Settings.from_env(), max_results=100, time_sampling_strata=4)
        adapter = TSharkAdapter(settings)
        start = datetime(2026, 2, 1, tzinfo=timezone.utc)
        end = start + timedelta(hours=8)
        process = _SyntheticTSharkProcess(lines)
        with patch.object(adapter, "_approved", return_value=Path("approved.pcap")), \
                patch("romulus.tools.tshark_client.shutil.which", return_value="tshark"), \
                patch("romulus.tools.tshark_client.subprocess.Popen", return_value=process) as popen:
            result = adapter.inspect(
                "approved.pcap",
                fields=["frame.number", "frame.time_epoch", "ip.src"],
                limit=limit,
                sample_start=start,
                sample_end=end,
                sampling={"version": 1, "strategy": "time_or_rank_stratified", "strata": 4},
            )
        self.assertNotIn("shell", popen.call_args.kwargs)
        return result

    def test_capped_stream_retains_matches_from_each_time_stratum(self):
        start = datetime(2026, 2, 1, tzinfo=timezone.utc)
        lines = [
            f'{index + 1}\t{(start + timedelta(minutes=30 * index)).timestamp()}\t192.0.2.{index + 1}\n'
            for index in range(16)
        ]

        result = self._inspect(lines)

        retained = [float(row["frame.time_epoch"]) for row in result["packets"]]
        self.assertEqual(result["matched_count"], 16)
        self.assertEqual(len(retained), 4)
        self.assertEqual(result["sampling"]["strategy"], "time_stratified_reservoir")
        self.assertEqual(result["sampling"]["covered_strata"], 4)
        self.assertEqual(result["sampling"]["retained_by_stratum"], [1, 1, 1, 1])
        self.assertEqual(result["sampling"]["matched_by_stratum"], [4, 4, 4, 4])
        self.assertLess(retained[0], (start + timedelta(hours=2)).timestamp())
        self.assertGreaterEqual(retained[-1], (start + timedelta(hours=6)).timestamp())

    def test_sampling_is_identical_for_repeated_complete_streams(self):
        start = datetime(2026, 2, 1, tzinfo=timezone.utc)
        lines = [
            f'{index + 1}\t{(start + timedelta(minutes=20 * index)).timestamp()}\t198.51.100.{index + 1}\n'
            for index in range(24)
        ]

        first = self._inspect(lines)
        second = self._inspect(lines)

        self.assertEqual(first["packets"], second["packets"])
        self.assertEqual(first["sampling"], second["sampling"])

    def test_malformed_timestamp_uses_disclosed_whole_stream_reservoir(self):
        start = datetime(2026, 2, 1, tzinfo=timezone.utc)
        lines = [
            f'1\t{start.timestamp()}\t203.0.113.1\n',
            '2\tnot-a-time\t203.0.113.2\n',
            f'3\t{(start + timedelta(hours=4)).timestamp()}\t203.0.113.3\n',
            f'4\t{(start + timedelta(hours=7)).timestamp()}\t203.0.113.4\n',
        ]

        result = self._inspect(lines, limit=2)

        self.assertEqual(result["matched_count"], 4)
        self.assertEqual(len(result["packets"]), 2)
        self.assertEqual(result["sampling"]["strategy"], "deterministic_reservoir")
        self.assertEqual(result["sampling"]["fallback_reason"], "malformed_or_missing_timestamp")


if __name__ == "__main__":
    unittest.main()
