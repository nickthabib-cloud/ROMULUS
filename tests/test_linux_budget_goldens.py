"""Fixed physical budgets preserve the synthetic stack's complete candidate golden."""
import pytest

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from tests import throughput_fixture as tf

CANDIDATE_GOLDENS = {
    4: (35, "02c5eb67a3b1a86948920d429194da593380330bd3cd7e66d720c6d898b5b15c"),
    8: (35, "02c5eb67a3b1a86948920d429194da593380330bd3cd7e66d720c6d898b5b15c"),
    16: (35, "02c5eb67a3b1a86948920d429194da593380330bd3cd7e66d720c6d898b5b15c"),
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
