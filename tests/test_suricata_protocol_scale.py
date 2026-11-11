"""Batched synthetic EVE scale proof; public format, no external traffic.

https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html
Each batch is released before the next. Peak/current memory is measured with
tracemalloc; it is Python allocation evidence, not a claim about backend throughput.
"""
import gc
import time
import tracemalloc

from romulus.evidence.normalize import normalize_hits
from tests.test_suricata_protocols import CASES, hit


def measure(records, batch_size=256):
    kinds = tuple(CASES)
    normalize_hits([hit(et, nid=f"warm-{et}") for et in kinds])
    gc.collect()
    tracemalloc.start()
    start = time.perf_counter()
    normalized = 0
    retained = []
    max_batch = 0
    for offset in range(0, records, batch_size):
        raw = [hit(kinds[i % len(kinds)], nid=f"scale-{i}")
               for i in range(offset, min(offset + batch_size, records))]
        events, skips, errors = normalize_hits(raw)
        assert not skips and not errors
        assert len(events) == len(raw)
        normalized += len(events)
        max_batch = max(max_batch, len(events))
        del raw, events
        if offset % (batch_size * 16) == 0:
            gc.collect()
            retained.append(tracemalloc.get_traced_memory()[0])
    elapsed = time.perf_counter() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"records": records, "normalized": normalized, "seconds": elapsed, "peak_bytes": peak,
            "current_bytes": current, "first_retained": retained[0], "last_retained": retained[-1],
            "max_batch_events": max_batch}


def test_two_hundred_thousand_eve_records_stream_with_bounded_memory():
    result = measure(200_000)
    print(result)
    assert result["normalized"] == 200_000
    assert result["max_batch_events"] <= 256
    assert result["peak_bytes"] < 16_000_000
    assert result["last_retained"] <= result["first_retained"] + 1_000_000
