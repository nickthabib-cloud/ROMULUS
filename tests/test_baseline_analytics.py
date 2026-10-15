import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def event(identifier, process, *, host="host-1", value=None):
    raw = {
        "@timestamp": "2026-10-15T12:00:00Z",
        "host": {"name": host},
        "process": {"name": process},
    }
    if value is not None:
        raw["network"] = {"bytes": value}
    return {"evidence_id": identifier, "observed_at": raw["@timestamp"],
            "source": "elasticsearch", "source_family": "host", "raw": raw}


def definition(identifier, primitive, **execution):
    return {"id": identifier, "title": identifier, "base_score": 25, "specificity": 70,
            "attack_techniques": ["T1059"], "follow_up": ["Review baseline lead."],
            "benign_explanations": ["Expected change."],
            "execution": {"status": "executable", "execution_kind": "baseline",
                "primitive": primitive, "source_families": ["host"], **execution}}


class BaselineEvaluationTests(unittest.TestCase):
    def test_flat_dotted_fields_are_evaluated_like_nested_fields(self):
        from romulus.intelligence.baseline_analytics import evaluate_baselines

        rule = definition("first", "first_seen", scope_fields=["host.name"],
                          value_fields=["process.name"], warmup_min=1)
        state = {"first": {"schema_version": 1, "observations": 1,
                           "scope_values": {"host-1": {"cmd.exe": 1}}}}
        row = {
            "evidence_id": "E-FLAT", "observed_at": "2026-10-15T12:00:00Z",
            "source": "elasticsearch", "source_family": "host",
            "raw": {"host.name": "host-1", "process.name": "pwsh.exe"},
        }

        matches, _ = evaluate_baselines([row], [rule], state, None)

        self.assertEqual([candidate["analytic_id"] for candidate in matches], ["first"])

    def test_first_seen_waits_for_warmup_then_matches_new_value(self):
        from romulus.intelligence.baseline_analytics import evaluate_baselines

        rule = definition("first", "first_seen", scope_fields=["host.name"],
                          value_fields=["process.name"], warmup_min=3)
        warming = {"first": {"schema_version": 1, "observations": 2,
                             "scope_values": {"host-1": {"cmd.exe": 2}}}}
        ready = {"first": {"schema_version": 1, "observations": 3,
                           "scope_values": {"host-1": {"cmd.exe": 3}}}}

        matches, coverage = evaluate_baselines([event("E1", "pwsh.exe")], [rule], warming, None)
        self.assertEqual(matches, [])
        self.assertEqual(coverage["by_rule"]["first"]["state"], "warming")

        matches, coverage = evaluate_baselines([event("E1", "pwsh.exe")], [rule], ready, None)
        self.assertEqual([row["analytic_id"] for row in matches], ["first"])
        self.assertEqual(coverage["by_rule"]["first"]["state"], "matched")

    def test_prevalence_and_peer_rarity_use_prior_distinct_scopes(self):
        from romulus.intelligence.baseline_analytics import evaluate_baselines

        rule = definition("rare", "prevalence", scope_fields=["host.name"],
                          value_fields=["process.name"], warmup_min=4,
                          peer_min_scopes=4, max_prevalence=0.25)
        state = {"rare": {"schema_version": 1, "observations": 8,
                          "scope_values": {"h1": {"rare.exe": 1}, "h2": {"common.exe": 2},
                                           "h3": {"common.exe": 2}, "h4": {"common.exe": 3}},
                          "value_scopes": {"rare.exe": ["h1"], "common.exe": ["h2", "h3", "h4"]}}}

        matches, _ = evaluate_baselines([event("E1", "rare.exe", host="h5")], [rule], state, None)

        self.assertEqual([row["analytic_id"] for row in matches], ["rare"])

    def test_deviation_uses_prior_mean_and_variance(self):
        from romulus.intelligence.baseline_analytics import evaluate_baselines

        rule = definition("bytes", "deviation", scope_fields=["host.name"],
                          aggregation="sum", measure_field="network.bytes",
                          warmup_min=4, multiplier=3.0, zscore=3.0, minimum=100)
        state = {"bytes": {"schema_version": 1, "observations": 4,
                           "metrics": {"host-1": {"n": 4, "mean": 100.0, "m2": 0.0}}}}

        matches, _ = evaluate_baselines([event("E1", "curl", value=400)], [rule], state, None)

        self.assertEqual([row["analytic_id"] for row in matches], ["bytes"])

    def test_partial_source_or_history_never_becomes_negative(self):
        from romulus.intelligence.baseline_analytics import evaluate_baselines

        rule = definition("first", "first_seen", scope_fields=["host.name"],
                          value_fields=["process.name"], warmup_min=1)
        state = {"first": {"schema_version": 1, "observations": 1,
                           "scope_values": {"host-1": {"cmd.exe": 1}}}}
        outcomes = [{"source_family": "host", "status": "partial", "capped": True}]

        matches, coverage = evaluate_baselines([event("E1", "cmd.exe")], [rule], state, outcomes)

        self.assertEqual(matches, [])
        self.assertEqual(coverage["by_rule"]["first"]["state"], "partial")

    def test_updates_exclude_suspicious_evidence(self):
        from romulus.intelligence.baseline_analytics import build_baseline_updates

        rule = definition("first", "first_seen", scope_fields=["host.name"],
                          value_fields=["process.name"], warmup_min=1)
        updates = build_baseline_updates(
            [event("GOOD", "cmd.exe"), event("BAD", "evil.exe")], [rule], {}, {"BAD"}
        )

        self.assertIn("cmd.exe", updates["first"]["scope_values"]["host-1"])
        self.assertNotIn("evil.exe", updates["first"]["scope_values"]["host-1"])

    def test_persisted_value_and_metric_dimensions_are_bounded(self):
        from romulus.intelligence.baseline_analytics import build_baseline_updates, evaluate_baselines

        first = definition("first", "first_seen", scope_fields=["host.name"],
                           value_fields=["process.name"], warmup_min=1)
        deviation = definition("bytes", "deviation", scope_fields=["host.name"],
                               aggregation="sum", measure_field="network.bytes",
                               warmup_min=1, multiplier=2.0, zscore=2.0, minimum=1)
        evidence = [event("E1", "one.exe", host="host-1", value=10),
                    event("E2", "two.exe", host="host-2", value=20)]

        with patch("romulus.intelligence.baseline_analytics.MAX_DISTINCT_VALUES", 1), \
             patch("romulus.intelligence.baseline_analytics.MAX_SCOPES", 1):
            updates = build_baseline_updates(evidence, [first, deviation], {}, set())

        self.assertLessEqual(len(updates["first"]["value_scopes"]), 1)
        self.assertLessEqual(len(updates["first"]["scope_values"]), 1)
        self.assertLessEqual(len(updates["bytes"]["metrics"]), 1)
        self.assertTrue(updates["first"]["storage_limited"])
        self.assertTrue(updates["bytes"]["storage_limited"])

        _, coverage = evaluate_baselines(
            [event("E3", "one.exe", host="host-1")], [first],
            {"first": updates["first"]}, None,
        )
        self.assertEqual(coverage["by_rule"]["first"]["state"], "partial")
        self.assertIn("baseline_history_limit", coverage["by_rule"]["first"]["incomplete_sources"])

    def test_store_update_is_versioned_and_idempotent_per_hunt(self):
        from romulus.store import Store

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            state = {"schema_version": 1, "observations": 3}

            self.assertTrue(store.apply_baseline_update("HUNT-1", "rule-1", state, version=1))
            self.assertFalse(store.apply_baseline_update("HUNT-1", "rule-1", {"observations": 9}, version=1))
            self.assertEqual(store.load_baseline_states(["rule-1"])["rule-1"]["observations"], 3)

    def test_partial_hunt_never_updates_baseline(self):
        from romulus.intelligence.baseline_analytics import persist_completed_baselines
        from romulus.store import Store

        rule = definition("first", "first_seen", scope_fields=["host.name"],
                          value_fields=["process.name"], warmup_min=1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root / "data", root / "logs")
            result = persist_completed_baselines(
                store, "HUNT-PARTIAL", "partial", [event("E1", "cmd.exe")], [rule], {}, set()
            )

            self.assertEqual(result["status"], "skipped_incomplete_hunt")
            self.assertEqual(store.load_baseline_states(), {})

    def test_pack_reconciles_all_58_baseline_records(self):
        from romulus.intelligence.behavior_packs import load_behavior_packs

        records = load_behavior_packs()["baselines"]["records"]

        self.assertEqual(len(records), 58)
        self.assertTrue(all(row.get("execution", {}).get("status") in {"executable", "reference_only"}
                            for row in records))
        self.assertTrue(any(row["execution"]["status"] == "executable" for row in records))


if __name__ == "__main__":
    unittest.main()
