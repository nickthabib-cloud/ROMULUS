"""Fixed physical budgets preserve the synthetic stack's complete candidate golden."""
import pytest

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from tests import throughput_fixture as tf

# All budgets retain the same 40 candidates and complete citation detail (event ids of evidence epoch 17; with the
# evidence version set back to 16 the digest is the earlier one).
# Discovery and transfer executions already cited by a folded alert are not repeated as context.
# Shared execution and lineage state keep the 4 MiB candidate result identical to larger budgets.
CANDIDATE_GOLDENS = {16: (40, '363d07e1031765c85c876ebc804a086d9426014b2ce3a605edc91ac1f8ead28f'),
 4: (40, '363d07e1031765c85c876ebc804a086d9426014b2ce3a605edc91ac1f8ead28f'),
 8: (40, '363d07e1031765c85c876ebc804a086d9426014b2ce3a605edc91ac1f8ead28f')}


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
    # Only rule versions moved these candidates: under this exact physical budget, restoring the prior versions must
    # reproduce the prior decisions and citations digest.
    persistence = [row for row in snapshot["candidates"] if row["rule_id"] == "host.persistence_path_change"]
    assert persistence and {row["rule_version"] for row in persistence} == {"9"}
    previous = tf.with_prior_versions(snapshot)
    assert tf.deterministic_golden_digests(previous)["candidates"] == (
        "819d72ca4130a7d6bb0880ce317287c9c4afe69b183d931e86d63b93e91bd18c")
    assert (len(snapshot["candidates"]), tf.deterministic_golden_digests(snapshot)["candidates"]) == CANDIDATE_GOLDENS[mib]
