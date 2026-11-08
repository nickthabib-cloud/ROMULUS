"""Fixed physical budgets preserve the synthetic stack's complete candidate golden."""
import pytest

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from tests import throughput_fixture as tf

# All budgets retain the same 40 candidates and complete citation detail.
# Discovery and transfer executions already cited by a folded alert are not repeated as context.
# Shared execution and lineage state keep the 4 MiB candidate result identical to larger budgets.
CANDIDATE_GOLDENS = {16: (40, 'b270718bc7543ffb1b4636a9fb469890acedc77f9a75aea8c519fcf56733a45b'),
 4: (40, 'b270718bc7543ffb1b4636a9fb469890acedc77f9a75aea8c519fcf56733a45b'),
 8: (40, 'b270718bc7543ffb1b4636a9fb469890acedc77f9a75aea8c519fcf56733a45b')}


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
