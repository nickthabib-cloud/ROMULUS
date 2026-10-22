"""Hot sets stay within the hunt's memory budget, measured with tracemalloc: every state is deep-sized from a random
sample across the whole hot set, so large states in the middle of the set, or a few hundred of them, are not
missed."""
import tracemalloc

import pytest

from romulus.detect.base import Playbook
from romulus.detect.bounded import KeyedStore, StateBudget, deep_size


class _Owner(Playbook):
    id = "test.memory"
    title = "test"
    families = ()


def _fill(tmp_path, n_keys: int, big: bool, small_ends: int, ports: int, total: int) -> tuple[int, KeyedStore]:
    owner = _Owner()
    owner.spill_dir = tmp_path
    owner.budget = StateBudget(tmp_path, disk_total=2**40, reserve=0, memory_total=total)
    store = KeyedStore(owner, "groups", 2_000_000)
    tracemalloc.start()
    try:
        for i in range(n_keys):
            is_big = big and small_ends <= i < n_keys - small_ends
            store.put((f"10.0.0.{i % 250}", f"10.1.{i // 250}.{i % 250}"), set(range(ports)) if is_big else {1})
        store.trim()
        traced = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()
    return traced, store


@pytest.mark.slow
@pytest.mark.parametrize(("n_keys", "small_ends"), [(900, 0), (1500, 16), (1500, 0)])
def test_large_states_stay_within_the_memory_total(tmp_path, n_keys, small_ends):
    total = 64 * 2**20
    traced, store = _fill(tmp_path, n_keys, True, small_ends, 10_000, total)
    assert store.on_disk > 0 and len(store) == n_keys
    assert traced <= total * 1.10, f"{traced / 2**20:.0f} MiB traced against a {total / 2**20:.0f} MiB budget"
    assert store.get(("10.0.0.100", "10.1.0.100")) == set(range(10_000))      # moved to disk, never forgotten
    store.owner.close_spill()


def test_a_few_hundred_large_states_are_measured(tmp_path):
    total = 8 * 2**20
    traced, store = _fill(tmp_path, 300, True, 0, 2_000, total)
    assert store.on_disk > 0
    assert traced <= total * 1.15, f"{traced / 2**20:.1f} MiB traced against a {total / 2**20:.0f} MiB budget"
    store.owner.close_spill()


def test_deep_size_counts_contents_and_slotted_objects():
    class Slotted:
        __slots__ = ("count", "names")

        def __init__(self):
            self.names = {f"name-{i}" for i in range(1000)}
            self.count = 3
    assert deep_size(set(range(10_000))) > 10_000 * 28
    assert deep_size(Slotted()) > 1000 * 50
    assert deep_size({"a": [1, 2, 3], "b": {"x": "y" * 1000}}) > 1000
