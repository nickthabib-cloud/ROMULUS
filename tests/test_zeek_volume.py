"""Zeek conn normalization streams at mission scale: bounded memory, linear time.

conn.log is the largest network log (one row per connection; hundreds of millions per hunt on a mission network).
Rows are normalized a page at a time, as a sweep reads them, and nothing may accumulate across pages. The proof:
every cache the normalizer keeps has a fixed size; once a first page has filled them, the memory Python holds
returns to the same level after each later page; and normalizing four times the rows takes about four times as long.
"""
import gc
import itertools
import time
import tracemalloc

import pytest

from romulus.evidence import zeek
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek_catalog import ZEEK_LOGS
from tests.fixtures import zeek_factory as zf
from tests.fixtures import zeek_logs as zl

PAGE = 250
PAGES = 16
# Bytes a page may leave behind once the caches are warm: allocator noise, never a page's events (hundreds of KiB).
RESIDUE = 64 * 2**10


def test_the_stamped_volume_rows_are_the_written_layout():
    for i, h in zip(range(200), zf.stream_conn_hits(200), strict=True):
        assert h == zf.malcolm(zf._volume_conn(i, zf.T0), f"malcolm-{i}"), i


def test_every_normalizer_cache_has_a_fixed_size():
    assert zeek._address.cache_info().maxsize == 65536
    assert zeek._parts.cache_info().maxsize == 4096
    assert zeek._compiled.cache_info().maxsize == 8192


def test_the_catalog_fits_its_caches():
    """A hunt over every shape and log never evicts a compiled path or a split path it will need again."""
    pairs = sum(len(spec.paths) for log in ZEEK_LOGS for spec in log.fields)
    paths = {path for log in ZEEK_LOGS for spec in log.fields for each in spec.paths.values() for path in each}
    assert pairs <= zeek._compiled.cache_info().maxsize // 2
    assert len(paths) <= zeek._parts.cache_info().maxsize // 2


def test_analyzer_log_memory_returns_to_its_level_after_every_page():
    """The analyzer logs stream as conn does: a page of mixed dns, http, ssl, files and notice rows leaves nothing
    behind once the caches are warm."""
    stream = zl.stream_rows(PAGE * (PAGES + 1))
    pages = (list(itertools.islice(stream, PAGE)) for _ in range(PAGES + 1))
    tracemalloc.start()
    try:
        warm, skips, errors = normalize_hits(next(pages))
        assert (skips, errors) == ({}, []) and len(warm) == PAGE
        del warm
        gc.collect()
        baseline = tracemalloc.get_traced_memory()[0]
        levels = []
        for page in pages:
            typed, _skips, _errors = normalize_hits(page)
            assert len(typed) == PAGE
            del typed, page
            gc.collect()
            levels.append(tracemalloc.get_traced_memory()[0] - baseline)
    finally:
        tracemalloc.stop()
    shown = [round(level / 2**10, 1) for level in levels]
    assert max(levels) <= RESIDUE, shown
    later = levels[PAGES // 2:]
    assert max(later) - min(later) <= RESIDUE // 4, shown


def test_windows_protocol_memory_returns_to_its_level_after_every_page():
    """SMB commands and DCE-RPC calls are the highest-volume Windows-protocol logs: a page of them (with SMB files,
    Kerberos, NTLM and LDAP searches) leaves nothing behind once the caches are warm."""
    stream = zl.stream_rows(PAGE * (PAGES + 1), kinds=zl.WINDOWS_STREAM)
    pages = (list(itertools.islice(stream, PAGE)) for _ in range(PAGES + 1))
    tracemalloc.start()
    try:
        warm, skips, errors = normalize_hits(next(pages))
        assert (skips, errors) == ({}, []) and len(warm) == PAGE
        del warm
        gc.collect()
        baseline = tracemalloc.get_traced_memory()[0]
        levels = []
        for page in pages:
            typed, _skips, _errors = normalize_hits(page)
            assert len(typed) == PAGE
            del typed, page
            gc.collect()
            levels.append(tracemalloc.get_traced_memory()[0] - baseline)
    finally:
        tracemalloc.stop()
    shown = [round(level / 2**10, 1) for level in levels]
    assert max(levels) <= RESIDUE, shown
    later = levels[PAGES // 2:]
    assert max(later) - min(later) <= RESIDUE // 4, shown


def _windows_seconds(rows: int) -> float:
    stream = zl.stream_rows(rows, kinds=zl.WINDOWS_STREAM)
    start = time.perf_counter()
    while page := list(itertools.islice(stream, 1000)):
        typed, skips, errors = normalize_hits(page)
        assert (skips, errors) == ({}, []) and len(typed) == len(page)
    return time.perf_counter() - start


@pytest.mark.slow
def test_four_times_the_windows_protocol_rows_take_about_four_times_as_long():
    small, large = _windows_seconds(10_000), _windows_seconds(40_000)
    assert large <= 8 * small, (round(small, 1), round(large, 1))


def test_memory_returns_to_its_level_after_every_page():
    stream = zf.stream_conn_hits(PAGE * (PAGES + 1), hosts=PAGE)
    pages = (list(itertools.islice(stream, PAGE)) for _ in range(PAGES + 1))
    tracemalloc.start()
    try:
        warm, skips, errors = normalize_hits(next(pages))
        assert (skips, errors) == ({}, []) and len(warm) == PAGE
        del warm
        gc.collect()
        baseline = tracemalloc.get_traced_memory()[0]
        levels = []
        for page in pages:
            typed, _skips, _errors = normalize_hits(page)
            assert len(typed) == PAGE
            del typed, page
            gc.collect()
            levels.append(tracemalloc.get_traced_memory()[0] - baseline)
    finally:
        tracemalloc.stop()
    shown = [round(level / 2**10, 1) for level in levels]
    assert max(levels) <= RESIDUE, shown
    # and it does not climb: the later pages leave what the middle ones did (a page's events would add hundreds of KiB)
    later = levels[PAGES // 2:]
    assert max(later) - min(later) <= RESIDUE // 4, shown


def _seconds(rows: int) -> float:
    stream = zf.stream_conn_hits(rows)
    start = time.perf_counter()
    while page := list(itertools.islice(stream, 1000)):
        typed, skips, errors = normalize_hits(page)
        assert (skips, errors) == ({}, []) and len(typed) == len(page)
    return time.perf_counter() - start


@pytest.mark.slow
def test_four_times_the_rows_take_about_four_times_as_long():
    small, large = _seconds(20_000), _seconds(80_000)
    # linear is 4x; the bound is generous so that a loaded machine does not fail it, and still far below the 16x a
    # quadratic cost would show
    assert large <= 8 * small, (round(small, 1), round(large, 1))
