"""Streaming name lookup cost and disk-backed source aggregation measurements."""
import gc
import json
import time
import tracemalloc
from ipaddress import ip_address

import pytest

from romulus.detect.netdef import SiteNetworks, install
from romulus.detect.service_catalog import NameTrie, ServiceCatalog
from tests.test_service_catalog import event


class EdgeCounter(dict):
    steps = 0

    def get(self, key, default=None):
        if key:
            type(self).steps += 1
        return super().get(key, default)


def counted(node):
    return EdgeCounter({key: counted(value) if isinstance(value, dict) else value for key, value in node.items()})


def test_trie_visits_labels_not_catalog_entries():
    for size in (50, 5000):
        trie = NameTrie((f"s{i}.service.example", f"service-{i}") for i in range(size))
        trie._root = counted(trie._root)
        for name, expected in [("x.s3.service.example", ("service-3",)), ("s9999.service.example", ())]:
            EdgeCounter.steps = 0
            assert trie.lookup(name) == expected
            assert EdgeCounter.steps <= len(name.split("."))


def lookup_measure(trie, rows):
    gc.collect()
    tracemalloc.start()
    start = time.perf_counter()
    hits = 0
    for index in range(rows):
        # Unique query labels defeat an accidental record-name memoization cache.
        query = f"q{index}.s{index % 10000}.service.example"
        hits += bool(trie.lookup(query))
    seconds = time.perf_counter() - start
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert hits == rows // 2
    return {"rows": rows, "seconds": seconds, "peak_python_bytes": peak, "hits": hits}


@pytest.mark.slow
def test_500m_name_lookup_cost_extrapolation_with_5000_suffixes():
    trie = NameTrie((f"s{i}.service.example", f"service-{i}") for i in range(5000))
    small = lookup_measure(trie, 50_000)
    large = lookup_measure(trie, 500_000)
    assert large["peak_python_bytes"] <= small["peak_python_bytes"] + 100_000
    estimate = 500_000_000 * large["seconds"] / large["rows"]
    print("SERVICE_CATALOG_LOOKUP_SCALE " + json.dumps({
        "suffixes": 5000, "small": small, "large": large,
        "extrapolated_rows": 500_000_000, "extrapolated_seconds": estimate,
        "actual_500m_run": False,
        "scope": "Name generation and trie lookup under tracemalloc; excludes normalization, storage and full hunt",
    }))


def source_measure(rows, directory):
    rule = ServiceCatalog()
    rule.spill_dir = directory
    gc.collect()
    tracemalloc.start()
    start = time.perf_counter()
    emitted = 0
    try:
        for index in range(rows):
            source = str(ip_address(0x0A000000 + index + 1))
            emitted += sum(1 for _ in rule.consume([event(source=source, n=index)]))
        assert emitted == rows and rule.evaluated == rows
        total = hosts = 0
        for match in rule.finalize():
            total += 1
            assert len(match.events) <= 2 and len(match.entities) <= 2
            if match.group_key.endswith("|fleet"):
                assert match.fleet_host_count == rows
                hosts = sum(1 for _ in match.fleet_hosts)
        assert total == rows + 1 and hosts == rows
        seconds = time.perf_counter() - start
        peak = tracemalloc.get_traced_memory()[1]
        disk_bytes = rule._spill.path.stat().st_size
        return {"rows": rows, "seconds": seconds, "peak_python_bytes": peak, "spill_bytes": disk_bytes}
    finally:
        tracemalloc.stop()
        rule.close_spill()


@pytest.mark.slow
def test_many_sources_spill_and_stream_instead_of_retaining_host_sets(tmp_path):
    definition = SiteNetworks.from_lists(["10.0.0.0/8"])
    install(definition)
    # The shared bounded network-address cache is not detector-owned state. Warm
    # all tested addresses before measuring the detector's growing SQLite rows.
    for index in range(20_000):
        definition.is_internal(ip_address(0x0A000000 + index + 1))
    small = source_measure(2_000, tmp_path / "small")
    large = source_measure(20_000, tmp_path / "large")
    assert large["peak_python_bytes"] <= small["peak_python_bytes"] + 2_000_000
    assert large["spill_bytes"] > small["spill_bytes"] * 5
    print("SERVICE_CATALOG_SOURCE_SCALE " + json.dumps({
        "small": small, "large": large,
        "scope": "Actual detector consume/finalize with streamed findings and memberships; shared bounded address cache warmed",
    }))
