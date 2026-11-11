"""Fixed physical budgets preserve the synthetic stack's complete candidate golden."""
import pytest

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from tests import throughput_fixture as tf

# All budgets retain the same 40 candidates and complete citation detail (event ids of evidence epoch 18; restoring
# epoch 17 reproduces the preceding complete snapshots).
# Discovery and transfer executions already cited by a folded alert are not repeated as context.
# Shared execution and lineage state keep the 4 MiB candidate result identical to larger budgets.
CANDIDATE_GOLDENS = {16: (40, 'f8cd05dca12fe55f5f8f408d8632e125ed9d22b9e731e928d5c53511cb7b7e48'),
 4: (40, 'f8cd05dca12fe55f5f8f408d8632e125ed9d22b9e731e928d5c53511cb7b7e48'),
 8: (40, 'f8cd05dca12fe55f5f8f408d8632e125ed9d22b9e731e928d5c53511cb7b7e48')}


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
    # Sweep-state budgets only: expansion seeds by the rule estimate, so the candidate golden isolates the sweep.
    snapshot = tf.run_stack(tmp_path, docs=tf.build(1), rank=False)
    # At this evidence epoch, changing only persistence contract metadata keeps its
    # separately captured decisions and citations under the same physical budget.
    persistence = [row for row in snapshot["candidates"] if row["rule_id"] == "host.persistence_path_change"]
    assert persistence and {row["rule_version"] for row in persistence} == {"9"}
    previous = dict(snapshot, candidates=[
        dict(row, rule_version="8") if row["rule_id"] == "host.persistence_path_change" else dict(row)
        for row in snapshot["candidates"]
    ])
    assert tf.deterministic_golden_digests(previous)["candidates"] == (
        "93593433453100bcd7a4e3a24a40ac1a34bdbeec399cda01eb4b6171c37bb7f5")
    assert (len(snapshot["candidates"]), tf.deterministic_golden_digests(snapshot)["candidates"]) == CANDIDATE_GOLDENS[mib]
