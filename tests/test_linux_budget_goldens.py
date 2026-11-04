"""Fixed physical budgets preserve the synthetic stack's complete candidate golden."""
import pytest

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from tests import throughput_fixture as tf

# Rule-version bumps only (the Zeek alert reading: see test_throughput_equality); with those versions restored the
# digest is the earlier 3b23f98dbf25d34c4921bbec2cba932991746ad9d4a11e8963988d7c8c421bee.
CANDIDATE_GOLDENS = {
    4: (35, "8c1125e496a977816f1a21d0f391e4408f6cac0edb7ce0c1e58281e8aa3bef6a"),
    8: (35, "8c1125e496a977816f1a21d0f391e4408f6cac0edb7ce0c1e58281e8aa3bef6a"),
    16: (35, "8c1125e496a977816f1a21d0f391e4408f6cac0edb7ce0c1e58281e8aa3bef6a"),
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
