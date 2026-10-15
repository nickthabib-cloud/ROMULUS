import unittest


def event(identifier, minute, signal, *, asset="host-1", actor="alice", path=None, source_family="host"):
    raw = {"host": {"name": asset}, "user": {"name": actor}}
    if path:
        raw["file"] = {"path": path}
    return {
        "evidence_id": identifier,
        "observed_at": f"2026-10-15T12:{minute:02d}:00Z",
        "source": "elasticsearch" if source_family == "host" else "arkime",
        "source_family": source_family,
        "asset": asset,
        "signals": [signal],
        "raw": raw,
    }


def definition(identifier="SEQ-1", *, order="ordered", joins=None, threshold=None, stages=None):
    stages = stages or [
        {"stage_id": "one", "signal": "download", "source_families": ["host"]},
        {"stage_id": "two", "signal": "execute", "source_families": ["host"]},
    ]
    execution = {
        "status": "executable",
        "execution_kind": "sequence",
        "order": order,
        "window_minutes": 10,
        "joins": joins or ["asset"],
        "join_mode": "all",
        "stages": stages,
    }
    if threshold is not None:
        execution["threshold"] = threshold
    return {
        "id": identifier,
        "title": identifier,
        "base_score": 80,
        "specificity": 90,
        "priority": "high",
        "attack_techniques": ["T1059"],
        "follow_up": ["Review sequence."],
        "benign_explanations": ["Authorized administration."],
        "execution": execution,
    }


class SequenceEvaluationTests(unittest.TestCase):
    def test_ordered_sequence_requires_time_order_same_asset_and_same_actor(self):
        from romulus.intelligence.sequence_analytics import evaluate_sequences

        rule = definition(joins=["asset", "actor"])
        good = [event("E1", 0, "download"), event("E2", 4, "execute")]
        wrong_order = [event("E3", 5, "download"), event("E4", 2, "execute")]
        wrong_actor = [event("E5", 0, "download"), event("E6", 2, "execute", actor="bob")]

        matched, _ = evaluate_sequences(good, [rule], None)
        reversed_match, _ = evaluate_sequences(wrong_order, [rule], None)
        actor_match, _ = evaluate_sequences(wrong_actor, [rule], None)

        self.assertEqual(matched[0]["evidence_ids"], ["E1", "E2"])
        self.assertEqual(reversed_match, [])
        self.assertEqual(actor_match, [])

    def test_unordered_threshold_counts_distinct_stages(self):
        from romulus.intelligence.sequence_analytics import evaluate_sequences

        stages = [{"stage_id": value, "signal": value, "source_families": ["host"]}
                  for value in ("id", "whoami", "groups", "sudo")]
        rule = definition(order="unordered_threshold", threshold=3, stages=stages)
        evidence = [event("E1", 0, "groups"), event("E2", 1, "id"), event("E3", 2, "sudo")]

        matches, _ = evaluate_sequences(evidence, [rule], None)

        self.assertEqual(matches[0]["matched_stage_ids"], ["groups", "id", "sudo"])

    def test_same_path_and_cross_source_join_are_enforced(self):
        from romulus.intelligence.sequence_analytics import evaluate_sequences

        stages = [
            {"stage_id": "host", "signal": "archive", "source_families": ["host"]},
            {"stage_id": "network", "signal": "upload", "source_families": ["network"]},
        ]
        rule = definition(joins=["asset", "path"], stages=stages)
        matching = [
            event("E1", 0, "archive", path="/tmp/a.zip"),
            event("E2", 3, "upload", path="/tmp/a.zip", source_family="network"),
        ]
        wrong_path = [matching[0], event("E3", 3, "upload", path="/tmp/b.zip", source_family="network")]

        matches, _ = evaluate_sequences(matching, [rule], None)
        rejected, _ = evaluate_sequences(wrong_path, [rule], None)

        self.assertEqual(matches[0]["source_families"], ["host", "network"])
        self.assertEqual(rejected, [])

    def test_failed_or_capped_required_source_is_partial_not_negative(self):
        from romulus.intelligence.sequence_analytics import evaluate_sequences

        rule = definition(stages=[
            {"stage_id": "host", "signal": "archive", "source_families": ["host"]},
            {"stage_id": "network", "signal": "upload", "source_families": ["network"]},
        ])
        outcomes = [
            {"source_family": "host", "status": "completed", "capped": False},
            {"source_family": "network", "status": "partial", "capped": True},
        ]

        matches, coverage = evaluate_sequences([], [rule], outcomes)

        self.assertEqual(matches, [])
        self.assertEqual(coverage["by_rule"]["SEQ-1"]["state"], "partial")
        self.assertIn("network", coverage["by_rule"]["SEQ-1"]["incomplete_sources"])

    def test_pack_reconciles_all_89_sequence_records(self):
        from romulus.intelligence.behavior_packs import load_behavior_packs

        records = load_behavior_packs()["sequences"]["records"]

        self.assertEqual(len(records), 89)
        self.assertTrue(all(row.get("execution", {}).get("status") in {"executable", "reference_only"}
                            for row in records))
        self.assertTrue(any(row["execution"]["status"] == "executable" for row in records))


if __name__ == "__main__":
    unittest.main()
