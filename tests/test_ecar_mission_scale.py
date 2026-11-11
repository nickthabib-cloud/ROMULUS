"""Synthetic streaming scale for https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md.

Object/action vocabulary: https://car.mitre.org/data_model/.
"""
from __future__ import annotations

import json
import tracemalloc
from itertools import islice
from time import perf_counter
from uuid import UUID

import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_ecar import ecar_hit

BATCH_SIZE = 256
BASELINE_RECORDS = 20_000
LARGE_RECORDS = 200_000


def _records(total):
    shapes = (
        ("PROCESS", "CREATE", {"image_path": r"C:\Windows\System32\cmd.exe", "command_line": "cmd.exe /c echo synthetic"}),
        ("FLOW", "START", {"src_ip": "192.0.2.1", "src_port": "50000", "dest_ip": "198.51.100.2", "dest_port": "443", "l4protocol": "tcp"}),
        ("FILE", "CREATE", {"file_path": r"C:\Tools\synthetic.txt"}),
        ("MODULE", "LOAD", {"module_path": r"C:\Windows\System32\example.dll"}),
        ("REGISTRY", "EDIT", {"key": r"HKCU\Software\Synthetic", "value": "Setting", "data": "1", "type": "REG_DWORD"}),
    )
    for number in range(total):
        hit = ecar_hit(*shapes[number % len(shapes)], id=str(UUID(int=number + 1)))
        hit["_id"] = str(number)
        yield hit


def _measure(total):
    records = _records(total)
    count = batches = 0
    tracemalloc.start()
    started = perf_counter()
    try:
        while batch := list(islice(records, BATCH_SIZE)):
            events, skips, errors = normalize_hits(batch)
            assert not skips and not errors
            assert len(events) == len(batch)
            count += len(events)
            batches += 1
        elapsed = perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert count == total
    assert batches == (total + BATCH_SIZE - 1) // BATCH_SIZE
    return {"records": count, "batches": batches, "seconds": round(elapsed, 3), "peak_bytes": peak}


@pytest.mark.slow
def test_ecar_streaming_200k_records_has_bounded_memory_and_near_linear_time():
    baseline = _measure(BASELINE_RECORDS)
    large = _measure(LARGE_RECORDS)
    print("ECAR_MISSION_SCALE " + json.dumps({"batch_size": BATCH_SIZE, "baseline": baseline, "large": large}, sort_keys=True))
    assert baseline["peak_bytes"] < 32 * 1024 * 1024
    assert large["peak_bytes"] < 32 * 1024 * 1024
    assert large["peak_bytes"] < baseline["peak_bytes"] * 2
    # A tenfold stream has a twofold per-record timing allowance for shared-host
    # variance; quadratic behavior would require roughly one hundredfold time.
    assert large["seconds"] < baseline["seconds"] * 20
