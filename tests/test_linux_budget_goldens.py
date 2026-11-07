"""Fixed physical budgets preserve the synthetic stack's complete candidate golden."""
import pytest

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from tests import throughput_fixture as tf

# All 35 finding identities and lanes are retained. Three beacons cite Arkime first and retain the equivalent
# Suricata witnesses; sensor attribution, cited timestamps and versions follow. See test_throughput_equality.
CANDIDATE_GOLDENS = {
    4: (35, "6531915996fd5b464b73a18dab49e7cbe2f679eccc4e71ec6618458629b3a4e3"),
    8: (35, "6531915996fd5b464b73a18dab49e7cbe2f679eccc4e71ec6618458629b3a4e3"),
    16: (35, "6531915996fd5b464b73a18dab49e7cbe2f679eccc4e71ec6618458629b3a4e3"),
}


@pytest.mark.parametrize("mib", CANDIDATE_GOLDENS)
def test_linux_stack_candidates_at_physical_byte_budget(mib, tmp_path, monkeypatch):
    tf.patched_sizes(monkeypatch)
    total = mib*2**20
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: StateBudget(stage_dir,disk_total=total,reserve=0))
    original = sw.Sweep.run_partition
    def run(self, *args, **kwargs):
        try:
            return original(self, *args, **kwargs)
        finally:
            assert sum(path.stat().st_size for path in tmp_path.rglob("*") if path.is_file()) <= total
    monkeypatch.setattr(sw.Sweep, "run_partition", run)
    snapshot = tf.run_stack(tmp_path, docs=tf.build(1))
    assert (len(snapshot["candidates"]), tf.digests(snapshot)["candidates"]) == CANDIDATE_GOLDENS[mib]
