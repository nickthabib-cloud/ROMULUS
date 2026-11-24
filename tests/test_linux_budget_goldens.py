"""Fixed physical budgets preserve the synthetic stack's complete candidate golden."""
import pytest

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from tests import throughput_fixture as tf

# All budgets retain the same 41 candidates and complete citation detail (event ids of evidence epoch 17; with the
# evidence version set back to 16 the digest is the earlier one).
# Discovery and transfer executions already cited by a folded alert are not repeated as context.
# Shared execution and lineage state keep the 4 MiB candidate result identical to larger budgets.
# Evidence version 21 rehashes the event ids (with the version set back to 20 the prior-version digest is 11b53998...).
# host.account_or_group_change 7->8 moves only that rule's version here (the throughput scenario's candidates
# digest with the prior versions restored is unchanged).
# pack@65 adds the access-log web shell rule's lead on the planted shell request (41 candidates); with that
# candidate left out and the prior versions restored the digest is the earlier one.
CANDIDATE_GOLDENS = {4: (41, '05c55f96f3109b84e55b15dd4549715d38fc1decf2073099c078559e9a33fe9c'),
 8: (41, '05c55f96f3109b84e55b15dd4549715d38fc1decf2073099c078559e9a33fe9c'),
 16: (41, '05c55f96f3109b84e55b15dd4549715d38fc1decf2073099c078559e9a33fe9c')}


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
    # Only rule versions moved these candidates at this evidence epoch (819d72ca... at epoch 17): under this exact
    # physical budget, restoring the prior versions must reproduce the prior decisions and citations digest.
    persistence = [row for row in snapshot["candidates"] if row["rule_id"] == "host.persistence_path_change"]
    assert persistence and {row["rule_version"] for row in persistence} == {"9"}
    previous = tf.with_prior_versions(dict(snapshot, candidates=[row for row in snapshot["candidates"]
                                                                 if row["rule_id"] != "web.access_log_web_shell"]))
    assert tf.deterministic_golden_digests(previous)["candidates"] == (
        "1ba3a7d45c7a29301e9ee253f8bee2f2fa1bbe288d5769f958940e4dfbb1878b")
    assert (len(snapshot["candidates"]), tf.deterministic_golden_digests(snapshot)["candidates"]) == CANDIDATE_GOLDENS[mib]
