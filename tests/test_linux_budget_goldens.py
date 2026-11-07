"""Fixed physical budgets preserve the synthetic stack's complete candidate golden."""
import pytest

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from tests import throughput_fixture as tf

# All 35 prior findings and lanes remain; nine findings are added. At 4 MiB, seven prior findings
# explicitly report reduced citation detail under the existing optional-citation headroom policy.
# The 8/16 MiB cases retain full current details, including both sensors for the three beacons.
# Producer/version and added-rule changes are explained in test_throughput_equality.
CANDIDATE_GOLDENS = {4: (44, '96527dfd128beba6fb241208f45c8bd1169ea2009e3156b5fa7cb56de1feac57'),
 8: (44, '7feeec34152612d99f26f626457058d6b4dc627289c56914d4985e6863675d37'),
 16: (44, '7feeec34152612d99f26f626457058d6b4dc627289c56914d4985e6863675d37')}


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
