"""Compute every golden the locked snapshot tests pin, at the current tree; writes JSON to $PINS."""
import json
import os

from romulus.detect.bounded import StateBudget
from romulus.hunt import sweep as sw
from romulus.hunt.pivot import PivotExecutor
from romulus.evidence.normalize import BootIntervals
from tests import test_throughput_equality as te
from tests import throughput_fixture as tf
from tests.test_linux_text_stack_r2 import run_text_stack

OUT = {}


def save():
    with open(os.environ["PINS"], "w", encoding="utf-8") as handle:
        json.dump(OUT, handle, sort_keys=True, indent=1)


def test_stack(tmp_path, monkeypatch):
    docs = tf.build(1)
    tf.patched_sizes(monkeypatch)
    ranked = tf.run_stack(tmp_path / "ranked", docs=docs)
    by_rule = tf.run_stack(tmp_path / "rule", docs=docs, rank=False)
    OUT["GOLDEN_STACK"] = tf.deterministic_golden_digests(ranked)
    OUT["GOLDEN_NON_BASELINE_SEMANTICS"] = te._non_baseline_semantic_digests(ranked)
    OUT["GOLDEN_STACK_BY_RULE_ESTIMATE"] = tf.deterministic_golden_digests(by_rule)
    OUT["GOLDEN_NON_BASELINE_SEMANTICS_BY_RULE_ESTIMATE"] = te._non_baseline_semantic_digests(by_rule)
    OUT["prior_rule_estimate"] = tf.deterministic_golden_digests(tf.with_prior_versions(by_rule))["candidates"]
    OUT["counts"] = {"ranked": len(ranked["candidates"]), "rule": len(by_rule["candidates"])}
    normalized, pivot = {}, {}
    executor = PivotExecutor(None, None, "h1", {})
    for target, records in sorted(docs.items()):
        normalized[target] = te._digest(te._normalized(records))
        normalized[f"{target}+boots"] = te._digest(te._normalized(records, BootIntervals()))
        for families in te.PIVOT_FAMILIES:
            events, errors = executor._normalize_pivot_records(records, set(families) if families else None)
            key = f"{target}:{','.join(sorted(families)) if families else '-'}"
            pivot[key] = te._digest({"events": [e.model_dump(mode="json") for e in events], "errors": errors})
    OUT["GOLDEN_NORMALIZED"], OUT["GOLDEN_PIVOT"] = normalized, pivot
    save()


def test_text(tmp_path, monkeypatch):
    snapshot, _trace, _docs = run_text_stack(tmp_path / "text", monkeypatch)
    OUT["GOLDEN_TEXT_STACK"] = tf.deterministic_golden_digests(snapshot)
    OUT["prior_text"] = tf.deterministic_golden_digests(tf.with_prior_versions(snapshot))["candidates"]
    save()


def test_budget(tmp_path, monkeypatch):
    tf.patched_sizes(monkeypatch)
    OUT["CANDIDATE_GOLDENS"], OUT["prior_budget"] = {}, {}
    for mib in (16, 4, 8):
        total = mib * 2**20
        monkeypatch.setattr(sw, "state_budget",
                            lambda settings, stage_dir, total=total: StateBudget(stage_dir, disk_total=total, reserve=0))
        snapshot = tf.run_stack(tmp_path / f"b{mib}", docs=tf.build(1), rank=False)
        OUT["CANDIDATE_GOLDENS"][mib] = [len(snapshot["candidates"]),
                                         tf.deterministic_golden_digests(snapshot)["candidates"]]
        OUT["prior_budget"][mib] = tf.deterministic_golden_digests(tf.with_prior_versions(snapshot))["candidates"]
    save()


def test_round7(tmp_path, monkeypatch):
    tf.patched_sizes(monkeypatch)
    budget = StateBudget(tmp_path, disk_total=int(4.1 * 2**20), reserve=0)
    monkeypatch.setattr(sw, "state_budget", lambda settings, stage_dir: budget)
    snapshot = tf.run_stack(tmp_path, docs=tf.build(4), rank=False)
    OUT["round7"] = {"broken": budget.broken, "count": len(snapshot["candidates"]),
                     "prior": tf.deterministic_golden_digests(tf.with_prior_versions(snapshot))["candidates"],
                     "current": tf.deterministic_golden_digests(snapshot)["candidates"]}
    save()
