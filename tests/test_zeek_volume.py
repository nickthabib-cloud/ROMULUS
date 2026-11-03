"""Zeek conn normalization streams at mission scale: a million rows in bounded memory and linear time.

conn.log is the largest network log (one row per connection; hundreds of millions per hunt on a mission network).
Rows are generated lazily and normalized a page at a time, as a sweep reads them; nothing may accumulate across
pages. The memory ceiling holds every live object Python allocates while the million rows go through (the page being
normalized, its typed events, and the normalizer's bounded caches), and the peak may not grow once the first
hundred thousand rows have filled those caches.
"""
import itertools
import time
import tracemalloc

import pytest

from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek import ZEEK_NORMALIZER
from tests.fixtures import zeek_factory as zf

ROWS = 1_000_000
PAGE = 1_000
CHUNK = 100_000
CEILING = 64 * 2**20
GROWTH = 8 * 2**20


def test_the_stamped_volume_rows_are_the_written_layout():
    for i, h in zip(range(200), zf.stream_conn_hits(200), strict=True):
        assert h == zf.malcolm(zf._volume_conn(i, zf.T0), f"malcolm-{i}"), i


@pytest.mark.slow
def test_a_million_conn_rows_normalize_in_bounded_memory_and_linear_time():
    stream = zf.stream_conn_hits(ROWS)
    events = 0
    chunk_times: list[float] = []
    first_chunk_peak = None
    tracemalloc.start()
    try:
        chunk_start = time.perf_counter()
        while page := list(itertools.islice(stream, PAGE)):
            typed, skips, errors = normalize_hits(page)
            assert (skips, errors) == ({}, []) and len(typed) == len(page)
            assert typed[-1].normalizer == ZEEK_NORMALIZER
            events += len(typed)
            del typed, page
            if events % CHUNK == 0:
                now = time.perf_counter()
                chunk_times.append(now - chunk_start)
                chunk_start = now
                if first_chunk_peak is None:
                    first_chunk_peak = tracemalloc.get_traced_memory()[1]
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert events == ROWS and len(chunk_times) == ROWS // CHUNK
    assert peak < CEILING, f"peak {peak / 2**20:.1f} MiB"
    assert peak <= first_chunk_peak + GROWTH, (
        f"peak grew from {first_chunk_peak / 2**20:.1f} MiB after {CHUNK:,} rows to {peak / 2**20:.1f} MiB")
    # linear: every hundred thousand rows take about as long as the first did
    assert max(chunk_times) <= 2.0 * chunk_times[0], [round(t, 1) for t in chunk_times]
