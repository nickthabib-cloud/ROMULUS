"""Bounded, typed output admission cannot mutate deterministic hunt state."""
from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from romulus.agent.admission import AgentAdmission
from romulus.agent.aliases import AliasBook
from romulus.agent.toolbox import Toolbox
from romulus.config import Settings
from romulus.evidence.typed import Outcome, TypedEvent, fv
from romulus.report.incidents import build_incident_graph
from romulus.store.db import make_engine, migrate, utcnow
from romulus.store.repo import Repo

T = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def _fixture(tmp_path, *, settings: Settings | None = None):
    repo = Repo(make_engine(tmp_path / "admission.sqlite"))
    migrate(repo.engine)
    repo.create_hunt("h1", {"window": {"start": T.isoformat(), "end": (T + timedelta(hours=1)).isoformat()},
                              "targets": ["host-index"], "ai_agent": {"requested": True}}, "d", "test")
    event = TypedEvent(id="ev1", family="process_exec", ts=T, host="web01", outcome=Outcome.success,
                       fields={"process.argv": fv(["id"], "fixture")}, raw=[], normalizer="test@1")
    repo.save_evidence("h1", [event], {}, None)
    repo.save_candidate({
        "id": "deterministic", "hunt_id": "h1", "rule_id": "host.test", "rule_version": "1",
        "claim": "A process execution was recorded", "claim_type": "observed_action", "event_ids": [event.id],
        "context_event_ids": [], "predicate_fields": [], "entities": [["host", "web01", "host"]],
        "ts": T, "severity": "high", "confidence": "high", "lane": "high", "priority": 10.0,
        "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
        "group_key": "det", "source_case_id": None, "source_anchor_id": None, "source_link_id": None,
    })
    session_id = "as-test"
    repo.save_agent_session({"id": session_id, "hunt_id": "h1", "hypothesis_id": None, "purpose": "investigate",
                             "state": "running", "tool_calls": 0, "summary": "", "started_at": utcnow(),
                             "ended_at": None})
    aliases = AliasBook(repo, "h1")
    finding = aliases.alias_for("F", "deterministic")
    evidence = aliases.alias_for("E", event.id)
    entity = repo.entity_for("h1", "host", "web01")
    entity_alias = aliases.alias_for("N", entity["id"])
    settings = settings or Settings(home=tmp_path)
    toolbox = Toolbox(repo, "h1", session_id=session_id)
    admission = AgentAdmission(settings, repo, "h1", session_id)
    admission.register(toolbox)
    admission.issue_aliases({"finding": finding, "evidence": evidence, "entity": entity_alias})
    return repo, toolbox, admission, finding, evidence, entity_alias


def _deterministic_graph(repo: Repo, *, include_agent_links: bool = False) -> dict:
    rows = [row for row in repo.candidates("h1", ["urgent", "high", "lead"])
            if row.get("provenance", "deterministic") == "deterministic"]
    views = [{"id": row["id"], "lane": row["lane"], "rule_id": row["rule_id"],
              "observed_at": str(row["ts"]) if row["ts"] is not None else None,
              "entities": row.get("entities") or [], "event_ids": row.get("event_ids") or [],
              "citations": [], "source_link_id": row.get("source_link_id")} for row in rows]
    return build_incident_graph(repo, "h1", views, include_agent_links=include_agent_links)


def test_output_admission_checks_alias_issue_claim_kind_lanes_duplicates_and_hypothesis_notes(tmp_path):
    settings = Settings(home=tmp_path, agent_max_findings=3)
    repo, toolbox, admission, finding, evidence, _entity = _fixture(tmp_path, settings=settings)
    unissued = AgentAdmission(Settings(home=tmp_path), repo, "h1", "as-test")
    unissued_toolbox = Toolbox(repo, "h1", session_id="as-test")
    unissued.register(unissued_toolbox)
    rejected = unissued_toolbox.execute("propose_finding", {
        "claim": "A process execution was observed", "claim_kind": "execution", "cites": [evidence],
        "lane": "high",
    })
    assert rejected["status"] == "refused" and "was not issued" in rejected["errors"][0]

    wrong_kind = toolbox.execute("propose_finding", {
        "claim": "A process execution was observed", "claim_kind": "execution", "cites": [finding],
        "lane": "high",
    })
    assert wrong_kind["status"] == "refused" and "expected E" in wrong_kind["errors"][0]
    unsupported = toolbox.execute("propose_finding", {
        "claim": "A network connection was observed", "claim_kind": "network", "cites": [evidence],
        "lane": "high",
    })
    assert unsupported["status"] == "refused" and "do not support a network claim" in unsupported["errors"][0]
    context = toolbox.execute("propose_finding", {
        "claim": "A process execution was observed", "claim_kind": "execution", "cites": [evidence],
        "lane": "context",
    })
    assert context["status"] == "refused" and "cannot be context" in context["errors"][0]

    duplicate = toolbox.execute("propose_finding", {
        "claim": "A process execution was observed", "claim_kind": "execution", "cites": [evidence],
        "lane": "high", "rationale": "This evidence already has a deterministic finding.",
    })
    assert duplicate["status"] == "complete" and duplicate["data"]["duplicate"] == finding
    assert repo.candidates("h1", ["urgent", "high", "lead"])[0]["provenance"] == "deterministic"
    assert repo.agent_notes("h1")[0]["target_id"] == "deterministic"

    opened = toolbox.execute("open_hypothesis", {"statement": "Review the process execution hypothesis"})
    assert opened["status"] == "complete"
    admission.issue_aliases(opened)
    hypothesis_alias = opened["data"]["hypothesis"]
    note = toolbox.execute("add_note", {"target": hypothesis_alias, "text": "Review this hypothesis note.",
                                         "cites": [evidence]})
    assert note["status"] == "complete"
    assert [row["kind"] for row in repo.agent_hypothesis_events(
        repo.agent_hypotheses("h1")[0]["id"])] == ["opened", "note"]

    second_event = TypedEvent(id="ev2", family="process_exec", ts=T + timedelta(seconds=1), host="web01",
                              outcome=Outcome.success,
                              fields={"process.argv": fv(["whoami"], "fixture:second")}, raw=[],
                              normalizer="test@1")
    repo.save_evidence("h1", [second_event], {}, None)
    second_evidence = AliasBook(repo, "h1").alias_for("E", second_event.id)
    admission.issue_aliases(second_evidence)

    urgent = toolbox.execute("propose_finding", {
        "claim": "An execution was proposed with a supported citation", "claim_kind": "execution",
        "cites": [second_evidence], "lane": "urgent",
    })
    assert urgent["status"] == "complete", urgent
    assert urgent["data"]["lane"] == "high"
    assert urgent["data"]["validation_notes"] == ["agent findings are capped at high"]
    mention = toolbox.execute("propose_finding", {
        "claim": "A typed record mentions a process command", "claim_kind": "mention",
        "cites": [second_evidence], "lane": "high",
    })
    assert mention["status"] == "complete" and mention["data"]["lane"] == "lead"
    assert "mention claims are capped at lead" in mention["data"]["validation_notes"]

    network_event = TypedEvent(id="net1", family="net_flow", ts=T + timedelta(seconds=2), host="sensor",
                               outcome=Outcome.unknown, fields={}, raw=[], normalizer="test@1")
    repo.save_evidence("h1", [network_event], {}, None)
    network_evidence = AliasBook(repo, "h1").alias_for("E", network_event.id)
    admission.issue_aliases(network_evidence)
    network = toolbox.execute("propose_finding", {
        "claim": "A network flow was recorded for analyst review", "claim_kind": "network",
        "cites": [network_evidence], "lane": "lead",
    })
    assert network["status"] == "complete" and network["data"]["claim_type"] == "network_observation"
    third_event = TypedEvent(id="ev3", family="process_exec", ts=T + timedelta(seconds=3), host="web01",
                             outcome=Outcome.success, fields={"process.argv": fv(["id"], "fixture:third")},
                             raw=[], normalizer="test@1")
    repo.save_evidence("h1", [third_event], {}, None)
    third_evidence = AliasBook(repo, "h1").alias_for("E", third_event.id)
    admission.issue_aliases(third_evidence)
    capped = toolbox.execute("propose_finding", {
        "claim": "Another execution proposal reaches the configured cap", "claim_kind": "execution",
        "cites": [third_evidence], "lane": "high",
    })
    assert capped["status"] == "refused" and "agent finding limit reached" in capped["errors"][0]
    assert "cap:findings" in admission.limits_hit


def test_agent_output_tools_preserve_deterministic_rows_coverage_and_incident_membership(tmp_path):
    settings = Settings(home=tmp_path, agent_max_hypotheses=12, agent_max_findings=12,
                        agent_max_links=18, agent_max_notes=120)
    repo, toolbox, admission, finding, evidence, entity = _fixture(tmp_path, settings=settings)
    repo.set_rule_cell("h1", "host.test", "1", "host-index", "p1", "evaluated_partial", 1, 2,
                       {"reason": "one shard was unavailable"})
    initial_candidates = [row for row in repo.candidates("h1") if row.get("provenance") != "agent"]
    initial_coverage = repo.rule_cells("h1")
    initial_expansion = repo.expansion_links("h1")
    initial_incidents = _deterministic_graph(repo)["incidents"]
    rng = random.Random(20261108)

    def action(index: int, name: str) -> dict:
        if name == "open_hypothesis":
            return {"statement": f"Review bounded hypothesis number {index}"}
        if name == "update_hypothesis":
            rows = repo.agent_hypotheses("h1")
            if not rows:
                return {"hypothesis": "H999", "note": "An intentionally unissued hypothesis."}
            hypothesis = rows[index % len(rows)]
            alias = AliasBook(repo, "h1").alias_for("H", hypothesis["id"])
            return {"hypothesis": alias, "note": f"Review result {index}.", "questions": []}
        if name == "propose_finding":
            return {"claim": f"A process execution candidate {index} was reviewed", "claim_kind": "execution",
                    "cites": [evidence], "lane": "high"}
        if name == "propose_link":
            return {"from": finding, "to": entity, "relation": "related", "cites": [evidence],
                    "rationale": f"Typed evidence suggests relation {index}."}
        if name == "add_note":
            return {"target": finding, "text": f"Bounded review note {index}.", "cites": [evidence]}
        if name == "request_rule":
            return {"pattern_description": f"Review possible reusable pattern number {index}.", "cites": [evidence]}
        return {"summary": f"The scripted output sequence completed at step {index}."}

    names = ("open_hypothesis", "update_hypothesis", "propose_finding", "propose_link",
             "add_note", "request_rule", "finish_session")
    for index in range(500):
        name = names[index] if index < len(names) else rng.choice(names)
        result = toolbox.execute(name, action(index, name))
        admission.issue_aliases(result)
        assert result["status"] in {"complete", "refused", "failed"}

    assert [row for row in repo.candidates("h1") if row.get("provenance") != "agent"] == initial_candidates
    assert repo.rule_cells("h1") == initial_coverage
    assert repo.expansion_links("h1") == initial_expansion
    graph = _deterministic_graph(repo, include_agent_links=True)
    membership = ("id", "finding_ids", "entity_node_ids", "timeline", "entry_point", "attack_techniques",
                 "attack_tactics", "hosts", "accounts", "open_ends")
    assert [{key: row[key] for key in membership} for row in graph["incidents"]] == [
        {key: row[key] for key in membership} for row in initial_incidents]
    assert graph["incidents"][0]["hypothesis_edges"] == len(graph["agent_links"])
    assert graph["agent_links"]
    assert all(row["style"] == "agent" and row["kind"] == "agent_hypothesis"
               and row["incident_role"] == "hypothesis" for row in graph["agent_links"])
    assert all(edge["style"] == "agent" and edge["kind"] == "agent_hypothesis"
               and edge["incident_role"] == "hypothesis" for edge in graph["edges"]
               if edge["kind"] == "agent_hypothesis")
    assert len(repo.agent_hypotheses("h1")) <= settings.agent_max_hypotheses
    assert sum(row.get("provenance") == "agent" for row in repo.candidates("h1")) <= settings.agent_max_findings
    assert len(repo.agent_links("h1")) <= settings.agent_max_links
    assert len(repo.agent_notes("h1")) <= settings.agent_max_notes
    assert {"cap:hypotheses", "cap:links", "cap:notes", "cap:rule_requests"} <= admission.limits_hit


def test_agent_output_caps_are_atomic_across_concurrent_writes(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    repo, _toolbox, _admission, _finding, _evidence, _entity = _fixture(tmp_path)
    now = utcnow()

    def race(write):
        barrier = Barrier(2)

        def attempt(index):
            barrier.wait(timeout=10)
            try:
                return bool(write(index))
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, (1, 2)))
        assert sum(outcomes) == 1

    def write_hypothesis(index):
        hypothesis_id = f"hyp-race-{index}"
        row = {"id": hypothesis_id, "hunt_id": "h1", "statement": f"Concurrent hypothesis {index}",
               "techniques": [], "entity_ids": [], "status": "open", "confidence": "low", "questions": [],
               "created_session_id": "as-test", "sessions_run": 0, "created_at": now, "updated_at": now}
        event = {"id": f"he-race-{index}", "hunt_id": "h1", "hypothesis_id": hypothesis_id,
                 "session_id": "as-test", "kind": "opened", "payload": {}, "created_at": now}
        return repo.create_agent_hypothesis(row, event, max_count=1)

    race(write_hypothesis)
    hypothesis = repo.agent_hypotheses("h1")[0]

    def write_finding(index):
        return repo.save_candidate({
            "id": f"agent-race-{index}", "hunt_id": "h1", "rule_id": "agent.finding", "rule_version": "1",
            "claim": f"A distinct concurrent candidate {index} was proposed", "claim_type": "observed_action",
            "event_ids": [], "context_event_ids": [], "predicate_fields": [], "entities": [], "ts": None,
            "severity": "high", "confidence": "low", "lane": "high", "priority": 1.0,
            "priority_reasons": [], "gate_results": {}, "benign_alternatives": [], "next_checks": [],
            "group_key": f"agent-race-{index}", "source_case_id": None, "source_anchor_id": None,
            "source_link_id": None, "provenance": "agent", "agent_hypothesis_id": None,
        }, max_agent_findings=1)

    race(write_finding)
    assert sum(row.get("provenance") == "agent" for row in repo.candidates("h1")) == 1

    def write_output(table_name, row_factory, count=1):
        race(lambda index: repo.save_agent_output(table_name, row_factory(index), max_count=count))

    write_output("agent_link", lambda index: {
        "id": f"alink-race-{index}", "hunt_id": "h1", "session_id": "as-test", "hypothesis_id": None,
        "from_kind": "finding", "from_id": "deterministic", "to_kind": "finding", "to_id": "deterministic",
        "relation": "related", "cites": [], "rationale": f"Concurrent relation {index}", "created_at": now,
    })
    write_output("agent_note", lambda index: {
        "id": f"an-race-{index}", "hunt_id": "h1", "session_id": "as-test", "target_kind": "finding",
        "target_id": "deterministic", "text": f"Concurrent note {index}", "cites": [],
        "suspicious_content": False, "created_at": now,
    })
    write_output("agent_rule_request", lambda index: {
        "id": f"arr-race-{index}", "hunt_id": "h1", "session_id": "as-test", "hypothesis_id": None,
        "pattern_description": f"Concurrent rule request {index}", "cites": [], "created_at": now,
    })

    def write_hypothesis_note(index):
        row = {"id": f"an-hyp-race-{index}", "hunt_id": "h1", "session_id": "as-test",
               "target_kind": "hypothesis", "target_id": hypothesis["id"], "text": f"Note {index}",
               "cites": [], "suspicious_content": False, "created_at": now}
        event = {"id": f"he-note-race-{index}", "hunt_id": "h1", "hypothesis_id": hypothesis["id"],
                 "session_id": "as-test", "kind": "note", "payload": {}, "created_at": now}
        return repo.save_agent_hypothesis_note(row, event, max_count=2)

    race(write_hypothesis_note)
    assert len(repo.agent_links("h1")) == len(repo.agent_rule_requests("h1")) == 1
    assert len(repo.agent_notes("h1")) == 2
