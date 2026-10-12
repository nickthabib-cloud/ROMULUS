import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from romulus.config import Settings
from romulus.investigation.sampling import (
    allocate_cap,
    rank_windows,
    sampling_policy,
    time_strata,
)


class SamplingContractTests(unittest.TestCase):
    def test_time_strata_are_stable_non_overlapping_and_cover_utc_interval(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = start + timedelta(hours=8)

        strata = time_strata(start, end, 4)

        self.assertEqual(
            strata,
            [
                {"index": 0, "start": start, "end": start + timedelta(hours=2), "include_end": False},
                {"index": 1, "start": start + timedelta(hours=2), "end": start + timedelta(hours=4), "include_end": False},
                {"index": 2, "start": start + timedelta(hours=4), "end": start + timedelta(hours=6), "include_end": False},
                {"index": 3, "start": start + timedelta(hours=6), "end": end, "include_end": True},
            ],
        )
        self.assertEqual(time_strata(start.astimezone(timezone(timedelta(hours=-5))), end, 4), strata)

    def test_time_strata_reject_reversed_or_empty_bounds(self):
        instant = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            time_strata(instant, instant, 4)
        with self.assertRaises(ValueError):
            time_strata(instant + timedelta(seconds=1), instant, 4)
        with self.assertRaises(ValueError):
            time_strata(instant.replace(tzinfo=None), instant, 4)

    def test_cap_allocation_is_exact_and_reduces_strata_for_small_caps(self):
        self.assertEqual(allocate_cap(10, 4), [3, 3, 2, 2])
        self.assertEqual(allocate_cap(2, 8), [1, 1])
        self.assertEqual(sum(allocate_cap(17, 8)), 17)
        with self.assertRaises(ValueError):
            allocate_cap(0, 4)

    def test_rank_windows_span_early_middle_and_late_results(self):
        self.assertEqual(
            rank_windows(100, 12, 4),
            [
                {"index": 0, "offset": 0, "length": 3},
                {"index": 1, "offset": 32, "length": 3},
                {"index": 2, "offset": 65, "length": 3},
                {"index": 3, "offset": 97, "length": 3},
            ],
        )
        self.assertEqual(rank_windows(3, 10, 8), [{"index": 0, "offset": 0, "length": 3}])

    def test_sampling_policy_is_code_controlled_and_configuration_is_bounded(self):
        with patch.dict(os.environ, {"TIME_SAMPLING_STRATA": "100"}, clear=False):
            settings = Settings.from_env()
        self.assertEqual(settings.time_sampling_strata, 24)
        self.assertEqual(
            sampling_policy(settings),
            {"version": 1, "strategy": "time_or_rank_stratified", "strata": 24},
        )


if __name__ == "__main__":
    unittest.main()
