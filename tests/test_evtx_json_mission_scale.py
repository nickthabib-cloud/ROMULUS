"""Synthetic EVTX JSON stream from the Windows event schema and evtx renderer contract.

https://github.com/omerbenamram/evtx
https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype
"""
import json
import tracemalloc
from itertools import islice
from time import perf_counter

import pytest

from romulus.evidence.normalize import normalize_hits
from tests.test_evtx_json import raw_hit

BATCH_SIZE = 256


def _records(count):
    for number in range(count):
        hit = raw_hit(data={"NewProcessName": r"C:\Windows\System32\cmd.exe", "NewProcessId": number + 100})
        hit["_id"] = str(number)
        hit["_source"]["Event"]["System"]["EventRecordID"] = number + 1
        yield hit


def _measure(count):
    records = _records(count)
    total = 0
    started = perf_counter()
    tracemalloc.start()
    try:
        while batch := list(islice(records, BATCH_SIZE)):
            events, skips, errors = normalize_hits(batch)
            assert not skips and not errors and len(events) == len(batch)
            total += len(events)
        seconds = perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert total == count
    return {"records": total, "seconds": seconds, "peak_bytes": peak, "batch_size": BATCH_SIZE}


@pytest.mark.slow
def test_evtx_json_streams_two_hundred_thousand_records_with_bounded_memory():
    small = _measure(20_000)
    large = _measure(200_000)
    print("EVTX_JSON_MISSION_SCALE " + json.dumps({"small": small, "large": large}, sort_keys=True))
    assert large["peak_bytes"] < 128 * 1024 * 1024
    assert large["peak_bytes"] < small["peak_bytes"] * 2 + 1024 * 1024
    # Ten times as many records must not accumulate per-hunt state or approach quadratic work.
    # The generous ratio allows scheduling noise on shared runners while rejecting 100x growth.
    assert large["seconds"] < small["seconds"] * 20
